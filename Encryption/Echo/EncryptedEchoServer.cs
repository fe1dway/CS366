using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.VisualBasic;

internal sealed class EncryptedEchoServer : EchoServerBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port) { }

    // todo: Step 1: Generate a RSA key (2048 bits) for the server.
    static RSA rsa = RSA.Create(2048);
    byte[] publicKey = rsa.ExportRSAPublicKey();
    byte[] privateKey = rsa.ExportRSAPrivateKey();
           
    /// <inheritdoc />
    public override string GetServerHello() {
        // todo: Step 1: Send the public key to the client in PKCS#1 format.
        // Encode using Base64: Convert.ToBase64String        
        string encodedKey = Convert.ToBase64String(publicKey);

        return encodedKey;
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        EncryptedMessage message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        
        Aes aes = Aes.Create();

        // todo: Step 2: Decrypt the message using hybrid encryption.
        byte[] decryptedHMACKey = rsa.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);
        byte[] decryptedAesKey = rsa.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);

        aes.Key = decryptedAesKey;

        // todo: Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad.
        byte[] decryptedMessage = aes.DecryptCbc(message.Message, message.AESIV, PaddingMode.PKCS7);
        byte[] calculatedMACbytes = HMACSHA256.HashData(decryptedHMACKey, decryptedMessage);

        bool verified = CryptographicOperations.FixedTimeEquals(calculatedMACbytes, message.HMAC);
        if (!verified) throw new InvalidSignatureException("Server recieved a bad hmac");
        
        // todo: Step 3: Return the decrypted and verified message from the server.
        
        return Settings.Encoding.GetString(decryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);


        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new SignedMessage(data, signature);
        
        return JsonSerializer.Serialize(message);
    }
}