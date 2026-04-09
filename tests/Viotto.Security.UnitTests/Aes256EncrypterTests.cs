using System;
using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class AES256EncrypterTests
{
    private readonly Base64Encoder _base64Encoder;
    private readonly Aes256Encrypter _sut;

    public AES256EncrypterTests()
    {
        _base64Encoder = new Base64Encoder();
        _sut = new Aes256Encrypter();
    }

    [Theory]
    [InlineData("0123456789ABCDEF", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0123456789abcdef", "rj4j0oXoIouySaSTartAsZvdKboPbPtGxIlzcE5VBWI=")]
    [InlineData("0123456789ABCDE", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "6Dzb9IX6sypRDLRHnoN+qQ==")]
    [InlineData("0123456789ABCDEF", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "qcbRXhI2Vpjjvc5KdwQ13VdNsZL2JoRmG8XLWFknrDA=")]
    [InlineData("0123456789ABCDEFG", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "qcbRXhI2Vpjjvc5KdwQ13e3n/p44DoTeYpIMojy3cZU=")]
    public void Encrypt_ShouldEncryptData(string inputText, string key, string iv, string expected)
    {
        // Arrange
        var inputBytes = Encoding.UTF8.GetBytes(inputText);
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var ivBytes = Encoding.UTF8.GetBytes(iv);

        // Act
        var output = _sut.Encrypt(inputBytes, keyBytes, ivBytes);

        // Assert
        var base64 = _base64Encoder.ToBase64(output);
        base64.Should().Be(expected);
    }

    [Theory]
    [InlineData("rj4j0oXoIouySaSTartAsZvdKboPbPtGxIlzcE5VBWI=", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0123456789abcdef", "0123456789ABCDEF")]
    [InlineData("6Dzb9IX6sypRDLRHnoN+qQ==", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "0123456789ABCDE")]
    [InlineData("qcbRXhI2Vpjjvc5KdwQ13VdNsZL2JoRmG8XLWFknrDA=", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "0123456789ABCDEF")]
    [InlineData("qcbRXhI2Vpjjvc5KdwQ13e3n/p44DoTeYpIMojy3cZU=", "abcdefghijklmnopqrstuvwxyz012345", "0123456789abcdef", "0123456789ABCDEFG")]
    public void Decrypt_ShouldDecryptData(string encryptedData, string key, string iv, string expected)
    {
        // Arrange
        var inputBytes = _base64Encoder.FromBase64(encryptedData);
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var ivBytes = Encoding.UTF8.GetBytes(iv);

        // Act
        var output = _sut.Decrypt(inputBytes, keyBytes, ivBytes);

        // Assert
        var base64 = Encoding.UTF8.GetString(output);
        base64.Should().Be(expected);
    }
}
