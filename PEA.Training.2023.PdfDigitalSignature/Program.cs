using iText.IO.Image;
using iText.IO.Util;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEA.Training._2023.PdfDigitalSignature
{
    internal class Program
    {
        public static readonly string DEST = "../../results/signatures/output/";

        public static readonly string SRC = "../../resources/pdfs/2023-10-27-08.07.41.429000000.ddbe9674-1fed-4de7-84a3-e032e59ea835.pdf";

        public static string IMG = "../../resources/encryption/sign.jpg";

        public void Sign(String src, String dest, X509Certificate[] chain, ICipherParameters pk,
            String digestAlgorithm, PdfSigner.CryptoStandard subfilter, String reason, String location,
            ICollection<ICrlClient> crlList, IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
        {
            PdfReader reader = new PdfReader(src);
            PdfSigner signer = new PdfSigner(reader, new FileStream(dest, FileMode.Create), new StampingProperties());

            // Create the signature appearance
            Rectangle rect = new Rectangle(100, 100, 200, 100);
            PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
            appearance
                .SetReason(reason)
                .SetLocation(location)

                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .SetReuseAppearance(false)
                .SetPageRect(rect)
                .SetPageNumber(1)
                .SetImage(ImageDataFactory.Create(IMG));
            signer.SetFieldName("sign_1");

            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm);

            // Sign the document using the detached mode, CMS or CAdES equivalent.
            signer.SignDetached(pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
        }

        public static void Main(String[] args)
        {
            DirectoryInfo directory = new DirectoryInfo(DEST);
            directory.Create();

            Properties properties = new Properties();

            /* This properties file should contain a CAcert certificate that belongs to the user,
             * according to the original sample purpose. However right now it contains a simple
             * self-signed certificate in p12 format, which serves as a stub.
             */
            properties.Load(new FileStream("../../resources/encryption/signkey.properties",
                FileMode.Open, FileAccess.Read));

            // Get path to the p12 file
            String path = properties.GetProperty("PRIVATE");

            // Get a password
            char[] pass = properties.GetProperty("PASSWORD").ToCharArray();

            Pkcs12Store pk12 = new Pkcs12Store(new FileStream(path, FileMode.Open, FileAccess.Read), pass);
            string alias = null;
            foreach (var a in pk12.Aliases)
            {
                alias = ((string)a);
                if (pk12.IsKeyEntry(alias))
                    break;
            }

            ICipherParameters pk = pk12.GetKey(alias).Key;
            X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
            X509Certificate[] chain = new X509Certificate[ce.Length];
            for (int k = 0; k < ce.Length; ++k)
            {
                chain[k] = ce[k].Certificate;
            }

            try
            {
                new Program().Sign(SRC, System.IO.Path.Combine(DEST, System.IO.Path.GetFileName(SRC)), chain, pk,
                DigestAlgorithms.SHA256, PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent", null, null, null, 0);
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex);
            }

            Console.WriteLine("Hello iText7!");
            Console.ReadKey();
        }
    }
}
