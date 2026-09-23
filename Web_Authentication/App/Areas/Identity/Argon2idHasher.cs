using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;
using System.Text;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using Argon2id.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        // todo: Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        // todo: Encode as "Base64(salt):Base64(digest)"
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
     
        Argon2id argon2 = new Argon2id(passwordBytes);
        argon2.DegreeOfParallelism = 8;
        argon2.Iterations = 4;
        argon2.MemorySize = 131072;
        argon2.Salt = salt;

        byte[] digest = argon2.GetBytes(32);
 
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
    
        Argon2id argon2 = new Argon2id(passwordBytes);
        argon2.DegreeOfParallelism = 8;
        argon2.Iterations = 4;
        argon2.MemorySize = 131072;
        argon2.Salt = salt;

        byte[] providedDigest = argon2.GetBytes(32);
        
        bool verified = CryptographicOperations.FixedTimeEquals(providedDigest, originalDigest);

        if (verified) {
            return PasswordVerificationResult.Success;
        }
        else {
            return PasswordVerificationResult.Failed;
        }

    }

}