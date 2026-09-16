using LibraSys.Api;

namespace LibraSys.Api.Tests;

public sealed class SecurityAndSchemaTests
{
    [Fact]
    public void Password_hashes_are_salted_and_verifiable()
    {
        var hasher = new PasswordHasher();
        var first = hasher.Hash("correct horse battery staple");
        var second = hasher.Hash("correct horse battery staple");

        Assert.NotEqual(first, second);
        Assert.True(hasher.Verify("correct horse battery staple", first));
        Assert.False(hasher.Verify("wrong password", first));
        Assert.False(hasher.Verify("password", "not-a-valid-hash"));
        Assert.False(hasher.Verify("password", "pbkdf2-sha256$1$bad$bad"));
    }

    [Fact]
    public void Initial_schema_contains_transactional_constraints()
    {
        var root = FindRepositoryRoot();
        var schema = File.ReadAllText(Path.Combine(root, "database", "migrations", "001_initial_schema.sql"));

        Assert.Contains("ENGINE=InnoDB", schema);
        Assert.Contains("idempotency_key", schema);
        Assert.Contains("CREATE TABLE fines", schema);
        Assert.Contains("CREATE TABLE payments", schema);
        Assert.Contains("FOR UPDATE", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Pbkdf2", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("MemberBelongsToUserAsync", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("/api/me/fines", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Member is not active.", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("public sealed record BorrowRequest(long CopyId, long MemberId, DateTime DueAt, string IdempotencyKey)", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("public sealed record PaymentRequest(long FineId, long MemberId, decimal Amount, string PaymentReference)", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("future due date", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("is not (\"good\" or \"damaged\" or \"lost\")", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("request.Condition == \"lost\"", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("/api/auth/logout", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("revoked_at=UTC_TIMESTAMP()", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("WriteAuditAsync", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("health/ready", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("LibraryDatabaseHealthCheck", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("CancelAfter(TimeSpan.FromSeconds(3))", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        var connectionSettings = File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "appsettings.json"));
        Assert.DoesNotContain("${LIBRASYS_DB_PASSWORD}", connectionSettings);
        Assert.Contains("connectionString.Contains(\"${\"", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        var program = File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs"));
        Assert.Contains("if (app.Environment.IsDevelopment())", program);
        Assert.Contains("app.UseSwaggerUI();", program);
        var frontend = File.ReadAllText(Path.Combine(root, "frontend", "index.html"));
        Assert.Contains("/api/me/fines", frontend);
        Assert.Contains("/api/reports/overdue", frontend);
        Assert.Contains("escapeHtml", frontend);
        Assert.Contains("api/auth/logout", frontend);
        Assert.Contains("sessionStorage.removeItem('librasys_token')", frontend);
        Assert.Contains("'Bearer '+token", frontend);
        var appSettings = File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "appsettings.json"));
        Assert.Contains("\"AllowedOrigins\": []", appSettings);
        Assert.Contains("AddCors", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("UseCors(\"frontend\")", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("AddRateLimiter", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("PermitLimit = 10", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("RequireRateLimiting(\"login\")", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("RetryAfter", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Page must be at least 1.", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Search text is too long.", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Fine recipient must be an active member.", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("Borrowing does not belong to the fine recipient.", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("SELECT member_id FROM borrowings WHERE borrowing_id=@BorrowingId FOR UPDATE", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
        Assert.Contains("WHERE idempotency_key=@IdempotencyKey", File.ReadAllText(Path.Combine(root, "src", "LibraSys.Api", "Program.cs")));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "README.md")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
