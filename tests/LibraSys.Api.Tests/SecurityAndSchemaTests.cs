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
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "README.md")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
