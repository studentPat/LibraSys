using System.Data;
using System.Security.Cryptography;
using Dapper;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.RateLimiting;
using MySqlConnector;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = static (context, cancellationToken) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        return ValueTask.CompletedTask;
    };
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("frontend", policy =>
    {
        if (allowedOrigins.Length > 0)
            policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod();
    });
});
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddScoped<IDbConnection>(_ =>
    new MySqlConnection(builder.Configuration.GetConnectionString("LibraryDatabase")));
builder.Services.AddScoped<LibraryService>();
builder.Services.AddHealthChecks()
    .AddCheck<LibraryDatabaseHealthCheck>("mysql", tags: new[] { "ready" });
builder.Services.AddAuthentication(BearerTokenDefaults.AuthenticationScheme)
    .AddBearerToken();
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();
app.UseExceptionHandler();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors("frontend");
app.UseRateLimiter();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (context, next) =>
{
    var header = context.Request.Headers.Authorization.ToString();
    if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        var service = context.RequestServices.GetRequiredService<LibraryService>();
        var principal = await service.AuthenticateTokenAsync(header[7..], context.RequestAborted);
        if (principal is not null) context.User = principal;
    }
    await next();
});
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});

app.MapPost("/api/auth/login", async (LoginRequest request, LibraryService service, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        return Results.BadRequest(new { error = "Username and password are required." });
    var result = await service.LoginAsync(request, ct);
    return result is null ? Results.Unauthorized() : Results.Ok(result);
}).RequireRateLimiting("login");

app.MapPost("/api/auth/logout", async (HttpContext http, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    var authorization = http.Request.Headers.Authorization.ToString();
    var token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? authorization["Bearer ".Length..]
        : string.Empty;
    await service.RevokeSessionAsync(token, UserId(http.User), ct);
    return Results.NoContent();
});

app.MapGet("/api/catalog", async (string? search, int? page, int? pageSize, LibraryService service, CancellationToken ct) =>
{
    if (page is < 1) return Results.BadRequest(new { error = "Page must be at least 1." });
    if (search?.Length > 200) return Results.BadRequest(new { error = "Search text is too long." });
    return Results.Ok(await service.SearchBooksAsync(search, page ?? 1, Math.Clamp(pageSize ?? 20, 1, 100), ct));
});

app.MapGet("/api/members/{membershipNumber}", async (HttpContext http, string membershipNumber, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    var member = await service.GetMemberAsync(membershipNumber, ct);
    if (member is null) return Results.NotFound();
    if (!IsStaff(http.User) && member.UserId != UserId(http.User)) return Results.Forbid();
    return Results.Ok(member);
});

app.MapPost("/api/circulation/borrow", async (HttpContext http, BorrowRequest request, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.IsInRole("librarian") && !http.User.IsInRole("admin")) return Results.Forbid();
    try { return Results.Ok(await service.BorrowAsync(request, UserId(http.User), ct)); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

app.MapPost("/api/circulation/return", async (HttpContext http, ReturnRequest request, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.IsInRole("librarian") && !http.User.IsInRole("admin")) return Results.Forbid();
    try { return Results.Ok(await service.ReturnAsync(request, UserId(http.User), ct)); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

app.MapPost("/api/reservations", async (HttpContext http, ReservationRequest request, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    if (!IsStaff(http.User) && !await service.MemberBelongsToUserAsync(request.MemberId, UserId(http.User), ct))
        return Results.Forbid();
    try { return Results.Ok(await service.ReserveAsync(request, ct)); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

app.MapGet("/api/reports/overdue", async (HttpContext http, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.IsInRole("librarian") && !http.User.IsInRole("admin")) return Results.Forbid();
    return Results.Ok(await service.OverdueAsync(ct));
});

app.MapPost("/api/fines", async (HttpContext http, FineRequest request, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.IsInRole("librarian") && !http.User.IsInRole("admin")) return Results.Forbid();
    try { return Results.Ok(await service.CreateFineAsync(request, ct)); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

app.MapGet("/api/members/{memberId:long}/fines", async (HttpContext http, long memberId, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    if (!IsStaff(http.User) && !await service.MemberBelongsToUserAsync(memberId, UserId(http.User), ct))
        return Results.Forbid();
    return Results.Ok(await service.MemberFinesAsync(memberId, ct));
});

app.MapGet("/api/me/fines", async (HttpContext http, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    return Results.Ok(await service.MemberFinesForUserAsync(UserId(http.User), ct));
});

app.MapPost("/api/payments", async (HttpContext http, PaymentRequest request, LibraryService service, CancellationToken ct) =>
{
    if (!http.User.IsInRole("librarian") && !http.User.IsInRole("admin")) return Results.Forbid();
    try { return Results.Ok(await service.PayFineAsync(request, UserId(http.User), ct)); }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
});

app.Run();

static bool IsStaff(System.Security.Claims.ClaimsPrincipal user) =>
    user.IsInRole("librarian") || user.IsInRole("admin");

static long UserId(System.Security.Claims.ClaimsPrincipal user) =>
    long.TryParse(user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value, out var id) ? id : 0;

public sealed record LoginRequest(string Username, string Password);
public sealed record LoginResponse(long UserId, string DisplayName, string[] Roles, string Token);
public sealed record BorrowRequest(long CopyId, long MemberId, DateTime DueAt, string IdempotencyKey);
public sealed record ReturnRequest(long BorrowingId, string Condition);
public sealed record ReservationRequest(long BookId, long MemberId, string IdempotencyKey);
public sealed record FineRequest(long? BorrowingId, long MemberId, decimal Amount, string Reason, string IdempotencyKey);
public sealed record PaymentRequest(long FineId, long MemberId, decimal Amount, string PaymentReference);
public sealed record BookRow(long BookId, string Isbn, string Title, string? PublisherName, int? AvailableCopies);
public sealed record MemberRow(long MemberId, long? UserId, string MembershipNumber, string FullName, string Email, string Status);

public sealed class LibraryDatabaseHealthCheck(IConfiguration configuration) : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public async Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var connectionString = configuration.GetConnectionString("LibraryDatabase");
        if (string.IsNullOrWhiteSpace(connectionString) || connectionString.Contains("${", StringComparison.Ordinal))
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("Library database connection is not configured.");

        try
        {
            await using var connection = new MySqlConnection(connectionString);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await connection.OpenAsync(timeout.Token);
            await using var command = new MySqlCommand("SELECT 1", connection);
            await command.ExecuteScalarAsync(timeout.Token);
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("Library database health check timed out.");
        }
        catch (MySqlException ex)
        {
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("Library database is unavailable.", ex);
        }
    }
}

public sealed class PasswordHasher
{
    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256$120000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string encoded)
    {
        try
        {
            var parts = encoded.Split('$');
            if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" ||
                !int.TryParse(parts[1], out var iterations) || iterations < 100_000)
                return false;
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            if (salt.Length < 16 || expected.Length < 32) return false;
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }
}

public sealed class LibraryService(IDbConnection db, PasswordHasher hasher)
{
    public async Task<LoginResponse?> LoginAsync(LoginRequest request, CancellationToken ct)
    {
        var user = await db.QuerySingleOrDefaultAsync<UserRecord>(
            new CommandDefinition("SELECT user_id UserId, display_name DisplayName, password_hash PasswordHash FROM users WHERE username=@Username AND is_active=1", request, cancellationToken: ct));
        if (user is null || !hasher.Verify(request.Password, user.PasswordHash)) return null;
        var roles = (await db.QueryAsync<string>(new CommandDefinition(
            "SELECT r.role_name FROM roles r JOIN user_roles ur ON ur.role_id=r.role_id WHERE ur.user_id=@UserId", new { user.UserId }, cancellationToken: ct))).ToArray();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var tokenHash = SHA256.HashData(Convert.FromHexString(token));
        await db.ExecuteAsync(new CommandDefinition(
            "INSERT INTO sessions(session_id,user_id,token_hash,expires_at) VALUES(UUID(),@UserId,@TokenHash,DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR))",
            new { user.UserId, TokenHash = tokenHash }, cancellationToken: ct));
        await WriteAuditAsync(user.UserId, "auth.login", "users", user.UserId.ToString(), ct);
        return new LoginResponse(user.UserId, user.DisplayName, roles, token);
    }

    public async Task RevokeSessionAsync(string token, long userId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        byte[] hash;
        try { hash = SHA256.HashData(Convert.FromHexString(token)); }
        catch (FormatException) { return; }
        await db.ExecuteAsync(new CommandDefinition(
            "UPDATE sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=@Hash AND user_id=@UserId AND revoked_at IS NULL",
            new { Hash = hash, userId }, cancellationToken: ct));
        await WriteAuditAsync(userId, "auth.logout", "sessions", null, ct);
    }

    private Task WriteAuditAsync(long actorUserId, string action, string entity, string? entityId, CancellationToken ct) =>
        db.ExecuteAsync(new CommandDefinition("""
            INSERT INTO audit_logs(actor_user_id, action_name, entity_name, entity_id)
            VALUES(@actorUserId, @action, @entity, @entityId)
            """, new { actorUserId, action, entity, entityId }, cancellationToken: ct));

    public async Task<System.Security.Claims.ClaimsPrincipal?> AuthenticateTokenAsync(string token, CancellationToken ct)
    {
        byte[] hash;
        try { hash = SHA256.HashData(Convert.FromHexString(token)); }
        catch (FormatException) { return null; }
        var record = await db.QuerySingleOrDefaultAsync<(long UserId, string Username)>(new CommandDefinition(
            "SELECT u.user_id UserId, u.username Username FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token_hash=@Hash AND s.revoked_at IS NULL AND s.expires_at > UTC_TIMESTAMP() AND u.is_active=1",
            new { Hash = hash }, cancellationToken: ct));
        if (record.UserId == 0) return null;
        var roles = await db.QueryAsync<string>(new CommandDefinition(
            "SELECT r.role_name FROM roles r JOIN user_roles ur ON ur.role_id=r.role_id WHERE ur.user_id=@UserId",
            new { record.UserId }, cancellationToken: ct));
        var identity = new System.Security.Claims.ClaimsIdentity("LibraSys");
        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, record.UserId.ToString()));
        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, record.Username));
        foreach (var role in roles) identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, role));
        return new System.Security.Claims.ClaimsPrincipal(identity);
    }

    public async Task<IEnumerable<BookRow>> SearchBooksAsync(string? search, int page, int pageSize, CancellationToken ct)
    {
        var term = string.IsNullOrWhiteSpace(search) ? null : $"%{search.Trim()}%";
        return await db.QueryAsync<BookRow>(new CommandDefinition("""
            SELECT b.book_id BookId, b.isbn Isbn, b.title Title, p.publisher_name PublisherName,
              SUM(c.status='available') AvailableCopies
            FROM books b LEFT JOIN publishers p ON p.publisher_id=b.publisher_id
              LEFT JOIN book_copies c ON c.book_id=b.book_id
            WHERE (@Term IS NULL OR b.title LIKE @Term OR b.isbn LIKE @Term)
            GROUP BY b.book_id, b.isbn, b.title, p.publisher_name
            ORDER BY b.title LIMIT @PageSize OFFSET @Offset
            """, new { Term = term, PageSize = pageSize, Offset = (page - 1) * pageSize }, cancellationToken: ct));
    }

    public Task<MemberRow?> GetMemberAsync(string number, CancellationToken ct) =>
        db.QuerySingleOrDefaultAsync<MemberRow>(new CommandDefinition(
            "SELECT member_id MemberId, user_id UserId, membership_number MembershipNumber, full_name FullName, email Email, status Status FROM members WHERE membership_number=@number", new { number }, cancellationToken: ct));

    public Task<bool> MemberBelongsToUserAsync(long memberId, long userId, CancellationToken ct) =>
        db.ExecuteScalarAsync<bool>(new CommandDefinition(
            "SELECT EXISTS(SELECT 1 FROM members WHERE member_id=@memberId AND user_id=@userId AND status <> 'closed')",
            new { memberId, userId }, cancellationToken: ct));

    public async Task<object> BorrowAsync(BorrowRequest request, long staffUserId, CancellationToken ct)
    {
        if (request.CopyId <= 0 || request.MemberId <= 0 || request.DueAt <= DateTime.UtcNow || string.IsNullOrWhiteSpace(request.IdempotencyKey))
            throw new InvalidOperationException("Copy, member, future due date, and idempotency key are required.");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await using var connection = (MySqlConnection)db;
            await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
            try
            {
                var copy = await connection.QuerySingleOrDefaultAsync<(long CopyId, string Status)>(
                    new CommandDefinition("SELECT copy_id CopyId, status Status FROM book_copies WHERE copy_id=@CopyId FOR UPDATE", request, tx, cancellationToken: ct));
                if (copy.CopyId == 0 || copy.Status != "available") throw new InvalidOperationException("Copy is not available.");
                var memberActive = await connection.ExecuteScalarAsync<bool>(new CommandDefinition(
                    "SELECT EXISTS(SELECT 1 FROM members WHERE member_id=@MemberId AND status='active')",
                    request, tx, cancellationToken: ct));
                if (!memberActive) throw new InvalidOperationException("Member is not active.");
                await connection.ExecuteAsync(new CommandDefinition(
                    "INSERT INTO borrowings(copy_id,member_id,borrowed_at,due_at,status,idempotency_key,created_by) VALUES(@CopyId,@MemberId,UTC_TIMESTAMP(),@DueAt,'active',@IdempotencyKey,@StaffUserId)",
                    new { request.CopyId, request.MemberId, request.DueAt, request.IdempotencyKey, StaffUserId = staffUserId }, tx, cancellationToken: ct));
                await connection.ExecuteAsync(new CommandDefinition("UPDATE book_copies SET status='on_loan', version=version+1 WHERE copy_id=@CopyId", request, tx, cancellationToken: ct));
                await tx.CommitAsync(ct);
                await WriteAuditAsync(staffUserId, "circulation.borrow", "borrowings", request.IdempotencyKey, ct);
                return new { request.CopyId, status = "active" };
            }
            catch (MySqlException ex) when (ex.Number == 1213 && attempt < 2) { await tx.RollbackAsync(ct); await Task.Delay(25 * (attempt + 1), ct); }
            catch (MySqlException ex) when (ex.Number == 1062)
            {
                await tx.RollbackAsync(ct);
                var existing = await connection.QuerySingleAsync<object>(new CommandDefinition(
                    "SELECT borrowing_id BorrowingId, copy_id CopyId, member_id MemberId, status Status FROM borrowings WHERE idempotency_key=@IdempotencyKey",
                    request, cancellationToken: ct));
                return existing;
            }
        }
        throw new InvalidOperationException("Borrow operation could not be completed after deadlock retries.");
    }

    public async Task<object> ReturnAsync(ReturnRequest request, long staffUserId, CancellationToken ct)
    {
        if (request.BorrowingId <= 0 || request.Condition is not ("good" or "damaged" or "lost"))
            throw new InvalidOperationException("A valid borrowing and return condition are required.");
        await using var connection = (MySqlConnection)db;
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var borrowing = await connection.QuerySingleOrDefaultAsync<(long CopyId, string Status)>(
            new CommandDefinition("SELECT copy_id CopyId, status Status FROM borrowings WHERE borrowing_id=@BorrowingId FOR UPDATE", request, tx, cancellationToken: ct));
        if (borrowing.CopyId == 0 || borrowing.Status != "active") throw new InvalidOperationException("Borrowing is not active.");
        await connection.ExecuteAsync(new CommandDefinition("UPDATE borrowings SET returned_at=UTC_TIMESTAMP(), status='returned', returned_condition=@Condition WHERE borrowing_id=@BorrowingId", request, tx, cancellationToken: ct));
        var copyStatus = request.Condition == "lost" ? "lost" : request.Condition == "damaged" ? "maintenance" : "available";
        await connection.ExecuteAsync(new CommandDefinition("UPDATE book_copies SET status=@copyStatus, version=version+1 WHERE copy_id=@CopyId", new { borrowing.CopyId, copyStatus }, tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        await WriteAuditAsync(staffUserId, "circulation.return", "borrowings", request.BorrowingId.ToString(), ct);
        return new { request.BorrowingId, status = "returned" };
    }

    public async Task<object> ReserveAsync(ReservationRequest request, CancellationToken ct)
    {
        if (request.BookId <= 0 || request.MemberId <= 0 || string.IsNullOrWhiteSpace(request.IdempotencyKey))
            throw new InvalidOperationException("Book, member, and idempotency key are required.");
        await using var connection = (MySqlConnection)db;
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var memberActive = await connection.ExecuteScalarAsync<long?>(new CommandDefinition(
            "SELECT member_id FROM members WHERE member_id=@MemberId AND status='active' FOR UPDATE",
            request, tx, cancellationToken: ct));
        if (memberActive is null) throw new InvalidOperationException("Member is not active.");
        try
        {
            await connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO reservations(book_id,member_id,status,idempotency_key) VALUES(@BookId,@MemberId,'queued',@IdempotencyKey)",
                request, tx, cancellationToken: ct));
            await tx.CommitAsync(ct);
            return new { request.BookId, status = "queued" };
        }
        catch (MySqlException ex) when (ex.Number == 1062)
        {
            await tx.RollbackAsync(ct);
            return await db.QuerySingleAsync<object>(new CommandDefinition(
                "SELECT reservation_id ReservationId, book_id BookId, member_id MemberId, status Status FROM reservations WHERE idempotency_key=@IdempotencyKey",
                request, cancellationToken: ct));
        }
    }

    public Task<IEnumerable<object>> OverdueAsync(CancellationToken ct) =>
        db.QueryAsync<object>(new CommandDefinition("""
            SELECT br.borrowing_id BorrowingId, m.membership_number MembershipNumber, b.title Title,
                   br.due_at DueAt, DATEDIFF(UTC_DATE(), DATE(br.due_at)) DaysOverdue
            FROM borrowings br JOIN members m ON m.member_id=br.member_id
            JOIN book_copies c ON c.copy_id=br.copy_id JOIN books b ON b.book_id=c.book_id
            WHERE br.status='active' AND br.due_at < UTC_TIMESTAMP()
            ORDER BY br.due_at
            """, cancellationToken: ct));

    public async Task<object> CreateFineAsync(FineRequest request, CancellationToken ct)
    {
        if (request.Amount <= 0 || string.IsNullOrWhiteSpace(request.Reason) || string.IsNullOrWhiteSpace(request.IdempotencyKey))
            throw new InvalidOperationException("A positive amount, reason, and idempotency key are required.");

        await using var connection = (MySqlConnection)db;
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        try
        {
            var member = await connection.QuerySingleOrDefaultAsync<(long MemberId, string Status)>(
                new CommandDefinition("SELECT member_id MemberId, status Status FROM members WHERE member_id=@MemberId FOR UPDATE", request, tx, cancellationToken: ct));
            if (member.MemberId == 0 || member.Status != "active")
                throw new InvalidOperationException("Fine recipient must be an active member.");

            if (request.BorrowingId is not null)
            {
                var borrowingMemberId = await connection.ExecuteScalarAsync<long?>(new CommandDefinition(
                    "SELECT member_id FROM borrowings WHERE borrowing_id=@BorrowingId FOR UPDATE",
                    request, tx, cancellationToken: ct));
                if (borrowingMemberId is null || borrowingMemberId.Value != request.MemberId)
                    throw new InvalidOperationException("Borrowing does not belong to the fine recipient.");
            }

            var fineId = await connection.ExecuteScalarAsync<long>(new CommandDefinition("""
                INSERT INTO fines(borrowing_id, member_id, amount, reason, status, idempotency_key)
                VALUES(@BorrowingId, @MemberId, @Amount, @Reason, 'unpaid', @IdempotencyKey);
                SELECT LAST_INSERT_ID();
                """, request, tx, cancellationToken: ct));
            await tx.CommitAsync(ct);
            return new { FineId = fineId, request.MemberId, request.Amount, status = "unpaid" };
        }
        catch (MySqlException ex) when (ex.Number == 1062)
        {
            await tx.RollbackAsync(ct);
            var existing = await db.QuerySingleAsync<object>(new CommandDefinition(
                "SELECT fine_id FineId, member_id MemberId, amount Amount, status Status FROM fines WHERE idempotency_key=@IdempotencyKey",
                request, cancellationToken: ct));
            return existing;
        }
    }

    public Task<IEnumerable<object>> MemberFinesAsync(long memberId, CancellationToken ct) =>
        db.QueryAsync<object>(new CommandDefinition("""
            SELECT fine_id FineId, borrowing_id BorrowingId, amount Amount, reason Reason,
                   status Status, assessed_at AssessedAt,
                   COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.fine_id=f.fine_id), 0) PaidAmount
            FROM fines f WHERE member_id=@memberId ORDER BY assessed_at DESC
            """, new { memberId }, cancellationToken: ct));

    public async Task<IEnumerable<object>> MemberFinesForUserAsync(long userId, CancellationToken ct)
    {
        var memberId = await db.ExecuteScalarAsync<long?>(new CommandDefinition(
            "SELECT member_id FROM members WHERE user_id=@userId AND status <> 'closed'",
            new { userId }, cancellationToken: ct));
        return memberId is null ? Array.Empty<object>() : await MemberFinesAsync(memberId.Value, ct);
    }

    public async Task<object> PayFineAsync(PaymentRequest request, long receivedBy, CancellationToken ct)
    {
        if (request.Amount <= 0 || string.IsNullOrWhiteSpace(request.PaymentReference))
            throw new InvalidOperationException("A positive amount and payment reference are required.");

        await using var connection = (MySqlConnection)db;
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var fine = await connection.QuerySingleOrDefaultAsync<(long FineId, long MemberId, decimal Amount, string Status)>(
            new CommandDefinition("""
                SELECT fine_id FineId, member_id MemberId, amount Amount, status Status
                FROM fines WHERE fine_id=@FineId FOR UPDATE
                """, request, tx, cancellationToken: ct));
        if (fine.FineId == 0 || fine.MemberId != request.MemberId || fine.Status == "waived")
            throw new InvalidOperationException("Fine is not payable for this member.");

        var paid = await connection.ExecuteScalarAsync<decimal>(new CommandDefinition(
            "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE fine_id=@FineId", request, tx, cancellationToken: ct));
        if (request.Amount > fine.Amount - paid)
            throw new InvalidOperationException("Payment exceeds the outstanding fine balance.");

        try
        {
            await connection.ExecuteAsync(new CommandDefinition("""
                INSERT INTO payments(fine_id, member_id, amount, payment_reference, received_by)
                VALUES(@FineId, @MemberId, @Amount, @PaymentReference, @ReceivedBy)
                """, new { request.FineId, request.MemberId, request.Amount, request.PaymentReference, ReceivedBy = receivedBy }, tx, cancellationToken: ct));
            var newStatus = request.Amount == fine.Amount - paid ? "paid" : "partially_paid";
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE fines SET status=@newStatus WHERE fine_id=@FineId", new { request.FineId, newStatus }, tx, cancellationToken: ct));
            await tx.CommitAsync(ct);
            await WriteAuditAsync(receivedBy, "fines.payment", "payments", request.PaymentReference, ct);
            return new { request.FineId, request.Amount, status = newStatus };
        }
        catch (MySqlException ex) when (ex.Number == 1062)
        {
            await tx.RollbackAsync(ct);
            throw new InvalidOperationException("Payment reference has already been used.");
        }
    }

    private sealed record UserRecord(long UserId, string DisplayName, string PasswordHash);
}
