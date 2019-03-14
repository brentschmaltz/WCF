// ----------------------------------------------------------------------------
// Utilities
//  - non WCF helpers
// ----------------------------------------------------------------------------

using System;

namespace WcfUtilities
{
    public static class Utilities
    {
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
    }
}

