namespace Viotto.Security;

public class Pkcs7
{
    public byte[] AddPadding(byte[] data, byte blockSize)
    {
        var padding = blockSize - (data.Length % blockSize);
        var result = new byte[data.Length + padding];
        result.AsSpan(data.Length).Fill((byte)padding);
        data.CopyTo(result);
        return result;
    }

    public byte[] RemovePadding(byte[] data, byte blockSize)
    {
        var padding = data[^1];

        if (padding == 0 || padding > blockSize || !data[^padding..].All(x => x == padding))
        {
            throw new InvalidOperationException("Padding PKCS7 inválido");
        }

        return data[..^padding];
    }
}
