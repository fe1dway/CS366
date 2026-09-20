using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    static RSA rsa = RSA.Create();
    /// <inheritdoc />
    public override void ProcessServerHello(string message) {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        int bytesRead; 
        
        byte[] decodedMessage = Convert.FromBase64String(message);

        rsa.ImportRSAPublicKey(decodedMessage, out bytesRead); 
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        Aes aes = Aes.Create();
        aes.Key = RandomNumberGenerator.GetBytes(32);
        byte[] aesText = aes.EncryptCbc(data, aes.IV, PaddingMode.PKCS7);

        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        byte[] hmacText = HMACSHA256.HashData(hmacKey, data);

        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] encryptedAesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] encryptedHMACKey = rsa.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);
        

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new EncryptedMessage(encryptedAesKey, aes.IV, aesText, encryptedHMACKey, hmacText);

        return JsonSerializer.Serialize(message);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        SignedMessage signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        bool verified = rsa.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (!verified) throw new InvalidSignatureException("Client recieved a bad hmac"); 

        // todo: Step 3: Return the message from the server.
        
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}