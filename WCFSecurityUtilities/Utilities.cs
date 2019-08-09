using System;

namespace WCFSecurityUtilities
{
    public static class Utilities
    {
        public class KeyTypes
        {
            public const string Asymmetric = "Asymmetric";
            public const string Bearer = "Bearer";
            public const string Symmetric = "Symmetric";
        }

        public static byte[] CloneBuffer( byte[] buffer, int offset, int len )
        {
            if ( offset < 0 )
                throw new ArgumentOutOfRangeException( "offset", "Negative offset passed to CloneBuffer." );
            if ( len < 1 )
                throw new ArgumentOutOfRangeException( "len", "Negative len passed to CloneBuffer." );

            if ( buffer.Length - offset < len )
                throw new ArgumentOutOfRangeException( "buffer, offset, len", "Invalid parameters to CloneBuffer: buffer.Length - offset < len." );

            byte[] copy = new byte[len];
            Buffer.BlockCopy( buffer, offset, copy, 0, len );
            return copy;
        }

        public static byte[] DecodeHexString( string hexString )
        {
            hexString = hexString.Trim();

            bool spaceSkippingMode = false;

            int i = 0;
            int length = hexString.Length;

            if ( ( length >= 2 ) &&
                ( hexString[0] == '0' ) &&
                ( ( hexString[1] == 'x' ) || ( hexString[1] == 'X' ) ) )
            {
                length = hexString.Length - 2;
                i = 2;
            }

            if ( length < 2 )
                throw new FormatException( "invalid" );

            byte[] sArray;

            if ( length >= 3 && hexString[i + 2] == ' ' )
            {
                if ( length % 3 != 2 )
                    throw new FormatException( "invalid" );

                spaceSkippingMode = true;

                // Each hex digit will take three spaces, except the first (hence the plus 1).
                sArray = new byte[length / 3 + 1];
            }
            else
            {
                if ( length % 2 != 0 )
                    throw new FormatException( "invalid" );

                spaceSkippingMode = false;

                // Each hex digit will take two spaces
                sArray = new byte[length / 2];
            }

            int digit;
            int rawdigit;
            for ( int j = 0; i < hexString.Length; i += 2, j++ )
            {
                rawdigit = ConvertHexDigit( hexString[i] );
                digit = ConvertHexDigit( hexString[i + 1] );
                sArray[j] = (byte)( digit | ( rawdigit << 4 ) );
                if ( spaceSkippingMode )
                    i++;
            }
            return ( sArray );
        }

        static int ConvertHexDigit( Char val )
        {
            if ( val <= '9' && val >= '0' )
                return ( val - '0' );
            else if ( val >= 'a' && val <= 'f' )
                return ( ( val - 'a' ) + 10 );
            else if ( val >= 'A' && val <= 'F' )
                return ( ( val - 'A' ) + 10 );
            else
                throw new FormatException( "invalid" );
        }


        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        public static bool AreEqual(byte[] a, byte[] b)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            byte[] a1, a2;

            if (((a == null) || (b == null))
            || (a.Length != b.Length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
            }
            else
            {
                a1 = a;
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }

    }
}

