using System;

namespace Bit.Core.Models.Table
{
    public class Grant
    {
        public string Key { get; set; }
        public string Type { get; set; }
        public string SubjectId { get; set; }
        public string SessionId { get; set; }
        public string ClientId { get; set; }
        public string Description { get; set; }
        public DateTime CreationDate { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public DateTime? ConsumedDate { get; set; }
        public string Data { get; set; }
    }
}
