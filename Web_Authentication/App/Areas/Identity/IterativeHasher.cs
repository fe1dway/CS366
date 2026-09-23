using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        // todo: Use 100,000 iterations and the SHA256 algorithm.
        // todo: Encode as "Base64(salt):Base64(digest)"

        byte[] salt = RandomNumberGenerator.GetBytes(32); 
        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
        byte[] saltedPassword = new byte[salt.Length + passwordBytes.Length];

        Array.Copy(salt, 0, saltedPassword, 0, salt.Length);
        Array.Copy(passwordBytes, 0, saltedPassword, salt.Length, passwordBytes.Length);
        

        byte[] digest = SHA256.HashData(saltedPassword);

        for (int i = 0; i < 100000; i++) {
            digest = SHA256.HashData(digest);
        }

        string encodedString = Utils.EncodeSaltAndDigest(salt, digest);

        return encodedString;
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        (byte[] salt, byte[] originalDigest) = Utils.DecodeSaltAndDigest(hashedPassword);
        
        byte[] passwordBytes = Encoding.ASCII.GetBytes(providedPassword);
        byte[] saltedPassword = new byte[salt.Length + passwordBytes.Length];

        Array.Copy(salt, 0, saltedPassword, 0, salt.Length);
        Array.Copy(passwordBytes, 0, saltedPassword, salt.Length, passwordBytes.Length);
        

        byte[] providedDigest = SHA256.HashData(saltedPassword);

        for (int i = 0; i < 100000; i++) {
            providedDigest = SHA256.HashData(providedDigest);
        }

        bool verified = CryptographicOperations.FixedTimeEquals(providedDigest, originalDigest);

        if (verified) {
            return PasswordVerificationResult.Success;
        }
        else {
            return PasswordVerificationResult.Failed;
        }
    }

}