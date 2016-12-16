// ----------------------------------------------------------------------------
// In memory keys for bindings
// ----------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;

namespace WcfKeys
{
    static public class KeyMaterial
    {
        public static string SelfSigned1024_SHA256
        {
            get
            {
                return @"MIIHBwIBAzCCBscGCSqGSIb3DQEHAaCCBrgEgga0MIIGsDCCA7kGCSqGSIb3DQEHAaCCA6oEggOmMIIDojCCA54GCyqGSIb3DQEMCgECoIICrjCCAqowHAYKKoZIhvcNAQwBAzAOBAiX6QpBO4EGpAICB9AEggKIVVwwasu5VeKCiUPjNbpGaj4r//RbNOUcGhZLlZICCxEwT4S7SvrNIEtw4vP3w2NfEcBaQtL6uu+eSF+xPp8eaVIVaEsysAMpmg3kP2Jt8xT6bTNvaR/5FjKvD/vSAsjDSdm3F3cugjBAq4xw/SdjO0gH8xOtx0vhYvD5ga0SN2JKkFW1xydw0b/pf7qD8t297OSLC+vaCwG4HCPj3t4XzV4SgFp0kWqJ0geAfddwC0EPCgpWEp2y+0Eh29xUVeRn8NHl4bdjv0OyLEyID94j6WQPr1ObmhMu1the7Rt3geWMdqzHQ6QWjCMVElUOGs8lXZU3Riz8AGM8QIuE4jqk20kBe2R59DUHdy7eYRnTHKsUcxjvHbq/jG7M9GB/m6eGk/smToupQEMYqzftydzICI2VAgcUB8YEf6M4ZjQxvjpn1rkTyMj8TcqyhA1fNcWxPAxbLMQEyFt25BvDyUaR0DlRiQN7GVOpXR1WEI25jIYrSFcnm830iyUKLwTxncRH57r+I7uwL65x0ZttvhFqaDAXofZKMw7uB8vy05hc/GvDVF6CVMr19fRCsjSgMH57dwzJTi6UZ6YVLu7ubigo2YM264Shq3aOno6BTgalhh1kkdl8EtPbHI4unvMg4v55B3lQVjL4o5H6vditvDFSyNoM0HazmiyzMrFzkEkj3zy1Es2b/alY5RuJceb8uyZxUhpigrg/B7ZwNIQTc+ZBEZDFWFgf18SjxQfMHq6JItwK9k65RpuC205T8cqwyZy6iY8j85Tt90Hw7OUaCbs/pznKcckktpnDW3Ca7bCstb8nWRFj403za34RREn7WL2ezvJqDt0tanCKVX/zrdjE1x4ADF/MkoTUMYHcMA0GCSsGAQQBgjcRAjEAMBMGCSqGSIb3DQEJFTEGBAQBAAAAMFcGCSqGSIb3DQEJFDFKHkgANwA1ADUAMQBlADAAMgBmAC0AYwBmADIAMQAtADQAOQBmADUALQA5AGUANgA4AC0AYgAzADIAZQBjAGYAYgBjADkAMABmADMwXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAdAByAG8AbgBnACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcjCCAu8GCSqGSIb3DQEHBqCCAuAwggLcAgEAMIIC1QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIlEr6OswpVr0CAgfQgIICqJd2Kcz+gOZRXE3j/8XbPBPJq3VKzsLRnCbvOhXLFwqiJAXzQjRpfAebtYhn9FuswQjMDQfYdim2Lg3rYb6VDjt61YDcPc2KTW4LkmPhFaKPMPtCDko3zflcnVODrt4A3/7Ku03WjFQs15n4SHA/rDtv725TwHx3isuUmky/cYfPscgiKv2AI2DLwe9D2BCJuAp4ZmTJ8o8i+XDix7ox8KXngWguIs1B4nomr62uio3u3OKJn0gUlVg2BgIzb4SSgddhCwxyWPF2oAW+pxI51o6QORwRI2yWNGcgnXojmsVG0urZ5pez2l3BE7w5qqT6QQSfktkmRQwi1ofHOIFLB1jhmxo8ANvXDEtB8YOixZ6XZURKyoZz9nqm+JPCBbHGLd62QFTUu+w8xz1eKvM2tAjj2GL9sK0JaZbUke9ijKhyINnB6pfYsmE3ja1VQ4epPRif8fZz8OKqLy+j0D94Opxq9FQgu1+qa5gvSzQ8skBPfeAlfoYlbEd/9QmIpFc5HHYn1puMz+pp46ilBal77FdKTunCRXQPFpfvUJYweJ4mTCJeHDktZb7xj8dl+lHZl5KJWRNEusasSRwzeNW4vZo466zSTUX8gSuU0OJsPo8q7znwKyVYh2dh813IQDd/1aFTKjPzjU5Wt7t5a2GwTr1wkMH4BP7UPlsryi0pv/EOLIEuMBBNDRDpAGEzkwCD/AECwv49SzFz3oGt3pzMReRB+NuRoIpJ6mw6aLmgJ9UoYAmMSRUL5VDTlLt2xP+ex3CRIpTa0NXhSYBPa37yTNP3ID7PWqXpECoY5w+QlYLTr+BMpp0L1F1D74punzjZc2pFnOgH+TPsTrVtrkWsk1iA+RHQ/AlC2JLnR+FVJSzktyrVC34j70cMYSqY4ev5A+fs2zgGp/4cMDcwHzAHBgUrDgMCGgQUUG+ZhmoN/MaNkyP3EWNX81zZoQQEFAuZPgiZ8hZN0m3+o4CLhQk4Uu6R";
            }
        }
    
        public static string SelfSigned1024_SHA256_Public
        {
            get
            {
                return "MIICWTCCAcKgAwIBAgIQPq8RWqoOL51G/qUxq7tBizANBgkqhkiG9w0BAQsFADA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADYwHhcNMTQxMjI2MTUyNzAwWhcNMzkxMjMxMjM1OTU5WjA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADYwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMl0ubbO3e3FpeMN2/gjz0YElurF0UCT25777CmNfzpvxtuvziUxa/ALMxmz+sVLzKb6kMuLNagU12cYZS3ksgntqxz8R/VyZO33hysNAMeMcdeOMhMm6ubTXEqqdHAb4TUPhme6o7Bvpcx3yPlxECoy6XE5A0VlYBgWzqMJN6F5AgMBAAGjajBoMGYGA1UdAQRfMF2AEKiIeaB2ShCC/Mrhyxg2Lf+hNzA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADaCED6vEVqqDi+dRv6lMau7QYswDQYJKoZIhvcNAQELBQADgYEAaqChtfN/l6xTcMItwFG9jhDPuWeLDXAplM0vSwbia1fIaAXdcFRSaH+5QwqoQSDROcfiWRbPNWhFXfzOj7FEBmtbGifiqDvHislRHYrqnz9FRKiay0KYn0tJ2RUsTlKxZNz0WVu9M05wJjYH4TB04ad5FhgxJZ2h/y1X+An4a/o=";
            }
        }

        public static X509Certificate2 CertSelfSigned1024_SHA256
        {
            get
            {
                return new X509Certificate2(Convert.FromBase64String(SelfSigned1024_SHA256), "SelfSigned1024_SHA256", X509KeyStorageFlags.PersistKeySet);
            }
        }

        public static X509Certificate2 CertSelfSigned1024_SHA256_Public
        {
            get
            {
                return new X509Certificate2(Convert.FromBase64String(SelfSigned1024_SHA256_Public), "SelfSigned1024_SHA256");
            }
       }
    }
}
