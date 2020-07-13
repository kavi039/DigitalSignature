package com.jvmfy.digitalsignature.signature;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.List;

@Slf4j
@Service
public class SigningService {

    private static final String KEY_STORE_TYPE = "jks";
    private final String keyStorePath;
    private final String keyStorePassword;
    private final String certificateAlias;
    private final String tsaUrl;
    private File imageFile = new File("/Users/kavitabora/Desktop/signature.png");

    public SigningService(@Value("${keystore.path}") String keyStorePath, @Value("${keystore.password}") String keyStorePassword, @Value("${keystore.certificate-alias}") String certificateAlias, @Value("${timestamp-authority.url}") String tsaUrl) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.certificateAlias = certificateAlias;
        this.tsaUrl = tsaUrl;
        System.out.println("..........    keyStorePath> "+ keyStorePath);
        System.out.println("..........    keyStorePassword> "+ keyStorePassword);
        System.out.println("..........    certificateAlias> "+ certificateAlias);
    }

    public byte[] signPdf(byte[] pdfToSign) {
        try {
            KeyStore keyStore = this.getKeyStore();
            Signature signature = new Signature(keyStore, this.keyStorePassword.toCharArray(), certificateAlias, tsaUrl);
            //create temporary pdf file
            File pdfFile = File.createTempFile("pdf", "");
            //write bytes to created pdf file
            FileUtils.writeByteArrayToFile(pdfFile, pdfToSign);

            //create empty pdf file which will be signed
            File signedPdf = File.createTempFile("signedPdf", "");
            //sign pdfFile and write bytes to signedPdf
            this.signDetached(signature, pdfFile, signedPdf);

            byte[] signedPdfBytes = Files.readAllBytes(signedPdf.toPath());

            //remove temporary files
            pdfFile.deleteOnExit();
            signedPdf.deleteOnExit();

            return signedPdfBytes;
        } catch (NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyStoreException e) {
            log.error("Cannot obtain proper KeyStore or Certificate", e);
        } catch (IOException e) {
            log.error("Cannot obtain proper file", e);
        }

        //if pdf cannot be signed, then return plain, not signed pdf
        return pdfToSign;
    }

    private KeyStore getKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        File key = ResourceUtils.getFile(keyStorePath);
        keyStore.load(new FileInputStream(key), keyStorePassword.toCharArray());
        return keyStore;
    }

    private void signDetached(SignatureInterface signature, File inFile, File outFile) throws IOException {
        if (inFile == null || !inFile.exists()) {
            throw new FileNotFoundException("Document for signing does not exist");
        }

        try (FileOutputStream fos = new FileOutputStream(outFile);
             PDDocument doc = PDDocument.load(inFile)) {
            signDetached(signature, doc, fos);
        }
    }

    private void signDetached(SignatureInterface signature, PDDocument document, OutputStream output) throws IOException {
        PDSignature pdSignature = new PDSignature();
        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        pdSignature.setName("jvmfy");
        pdSignature.setReason("Learn how to sign pdf with jvmfy.com!");

        // the signing date, needed for valid signature
        pdSignature.setSignDate(Calendar.getInstance());
        SignatureOptions signatureOptions = new SignatureOptions();
        Rectangle2D rect = new Rectangle2D.Float(292, 730, 150, 50);
        signatureOptions.setVisualSignature(createVisualSignatureTemplate(document, 0, createSignatureRectangle(document, rect)));
        signatureOptions.setPage(0);
        // register signature dictionary and sign interface
        document.addSignature(pdSignature, signature, signatureOptions);

        // write incremental (only for signing purpose)
        // use saveIncremental to add signature, using plain save method may break up a document
        document.saveIncremental(output);
    }

    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect)
    {
        float x = (float) humanRect.getX();
        float y = (float) humanRect.getY();
        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
        PDPage page = doc.getPage(0);
        PDRectangle rect = new PDRectangle();
        // signing should be at the same position regardless of page rotation.
        switch (page.getRotation())
        {
            case 90:
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                break;
            case 180:
                rect.setUpperRightX(page.getMediaBox().getWidth() - x);
                rect.setLowerLeftX(page.getMediaBox().getWidth() - x - width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
            case 270:
                rect.setLowerLeftY(page.getMediaBox().getHeight() - x - width);
                rect.setUpperRightY(page.getMediaBox().getHeight() - x);
                rect.setLowerLeftX(page.getMediaBox().getWidth() - y - height);
                rect.setUpperRightX(page.getMediaBox().getWidth() - y);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(page.getMediaBox().getHeight() - height - y);
                rect.setUpperRightY(page.getMediaBox().getHeight() - y);
                break;
        }
        return rect;
    }

    // create a template PDF document with empty signature and return it as a stream.
    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum, PDRectangle rect) throws IOException
    {
        try (PDDocument doc = new PDDocument())
        {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            float height = bbox.getHeight();
            Matrix initialScale = null;
            switch (srcDoc.getPage(pageNum).getRotation())
            {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 0:
                default:
                    break;
            }
            form.setBBox(bbox);
            PDFont font = PDType1Font.HELVETICA_BOLD;

            // from PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream))
            {
                // for 90Â° and 270Â° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null)
                {
                    cs.transform(initialScale);
                }

                // show background (just for debugging, to see the rect size + position)
                cs.setNonStrokingColor(Color.yellow);
                cs.addRect(-5000, -5000, 10000, 10000);
                cs.fill();

                // show background image
                // save and restore graphics if the image is too large and needs to be scaled
                cs.saveGraphicsState();
                cs.transform(Matrix.getScaleInstance(0.25f, 0.25f));
                PDImageXObject img = PDImageXObject.createFromFileByExtension(imageFile, doc);
                cs.drawImage(img, 0, 0);
                cs.restoreGraphicsState();

                // show text
                float fontSize = 10;
                float leading = fontSize * 1.5f;
//                cs.beginText();
//                cs.setFont(font, fontSize);
                cs.setNonStrokingColor(Color.black);
                cs.setLeading(leading);
                drawString(cs, fontSize, height, leading);
            }

            // no need to set annotations and /P entry

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    // Find an existing signature (assumed to be empty). You will usually not need this.
    private PDSignature findExistingSignature(PDAcroForm acroForm, String sigFieldName)
    {
        PDSignature signature = null;
        PDSignatureField signatureField;
        if (acroForm != null)
        {
            signatureField = (PDSignatureField) acroForm.getField(sigFieldName);
            if (signatureField != null)
            {
                // retrieve signature dictionary
                signature = signatureField.getSignature();
                if (signature == null)
                {
                    signature = new PDSignature();
                    // after solving PDFBOX-3524
                    // signatureField.setValue(signature)
                    // until then:
                    signatureField.getCOSObject().setItem(COSName.V, signature);
                }
                else
                {
                    throw new IllegalStateException("The signature field " + sigFieldName + " is already signed.");
                }
            }
        }
        return signature;
    }


    void drawString(PDPageContentStream contents, float fontSize, float height, float leading) throws IOException{
        String[] wrT = null;
        String s = null;
        String text = "Job Description: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque hendrerit lectus nec ipsum gravida placerat. Fusce eu erat orci. Nunc eget augue neque. Fusce arcu risus, pulvinar eu blandit ac, congue non tellus. Sed eu neque vitae dui placerat ultricies vel vitae mi. Vivamus vulputate nullam.";
        wrT = splitString(text);
        System.out.println("......."+wrT.length);

        for (int i = 0; i<= wrT.length-1 ; i++) {
            s = wrT[i];
            System.out.println(".......s....  "+s);
            contents.beginText();
            contents.setFont(PDType1Font.HELVETICA, 10);
            contents.newLineAtOffset(fontSize, 30f-10f*i);
            contents.showText(s);
            contents.endText();
        }
    }

    public String [] splitString(String text) {
        /* pdfBox doesnt support linebreaks. Therefore, following steps are requierd to automatically put linebreaks in the pdf
         * 1) split each word in string that has to be linefeded and put them into an array of string, e.g. String [] parts
         * 2) create an array of stringbuffer with (textlength/(number of characters in a line)), e.g. 280/70=5 >> we need 5 linebreaks!
         * 3) put the parts into the stringbuffer[i], until the limit of maximum number of characters in a line is allowed,
         * 4) loop until stringbuffer.length < linebreaks
         *
         */
        int linebreaks=text.length()/40; //how many linebreaks do I need?
        String [] newText = new String[linebreaks+1];
        String tmpText = text;
        String [] parts = tmpText.split(" "); //save each word into an array-element

        //split each word in String into a an array of String text.
        StringBuffer [] stringBuffer = new StringBuffer[linebreaks+1]; //StringBuffer is necessary because of manipulating text
        int i=0; //initialize counter
        int totalTextLength=0;
        for(int k=0; k<linebreaks+1;k++) {
            stringBuffer[k] = new StringBuffer();
            while(true) {
                if (i>=parts.length) break; //avoid NullPointerException
                totalTextLength=totalTextLength+parts[i].length(); //count each word in String
                if (totalTextLength>40) break; //put each word in a stringbuffer until string length is >80
                stringBuffer[k].append(parts[i]);
                stringBuffer[k].append(" ");
                i++;
            }
            //reset counter, save linebreaked text into the array, finally convert it to a string
            totalTextLength=0;
            newText[k] = stringBuffer[k].toString();
        }
        return newText;
    }
}
