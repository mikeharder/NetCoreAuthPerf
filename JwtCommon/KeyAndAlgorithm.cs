using Microsoft.IdentityModel.Tokens;

namespace JwtCommon
{
    public class KeyAndAlgorithm
    {
        public SecurityKey SigningKey { get; internal set; }
        public SecurityKey ValidationKey { get; internal set; }
        public string Algorithm { get; internal set; }
        public string AlgorithmDescription { get; internal set; }
    }
}
