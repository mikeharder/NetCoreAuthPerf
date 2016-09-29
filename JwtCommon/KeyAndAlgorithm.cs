using Microsoft.IdentityModel.Tokens;

namespace JwtCommon
{
    public class KeyAndAlgorithm
    {
        public SecurityKey Key { get; internal set; }
        public string Algorithm { get; internal set; }
        public string AlgorithmDescription { get; internal set; }
    }
}
