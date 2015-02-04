/*
 * Copyright (c) 2005-2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.sso.liferay.auth;

import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.security.auth.AuthException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.signature.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class Util {


    private static Properties properties = new Properties();

    private static boolean bootStrapped = false;

    private static Random random = new Random();

    private static final char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

    public static void doBootstrap() {
        if (!bootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                bootStrapped = true;
            } catch (ConfigurationException e) {
                System.err.println("Error in bootstrapping the OpenSAML2 library");
                e.printStackTrace();
            }
        }
    }

    public static XMLObject buildXMLObject(QName objectQName)
            throws Exception {
        XMLObjectBuilder builder = org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            throw new Exception("Unable to retrieve builder for object QName " + objectQName);
        }

        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }

    public static String createID() {
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);

        char[] chars = new char[40];

        for (int i = 0; i < bytes.length; i++) {
            int left = bytes[i] >> 4 & 0xF;
            int right = bytes[i] & 0xF;
            chars[(i * 2)] = charMapping[left];
            chars[(i * 2 + 1)] = charMapping[right];
        }

        return String.valueOf(chars);
    }

    public static XMLObject unmarshall(String authReqStr)
            throws IOException {
        try {
            doBootstrap();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(authReqStr.trim().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = org.opensaml.Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (ParserConfigurationException e) {
            throw new IOException("Error in constructing AuthRequest from the encoded String ", e);
        } catch (SAXException e) {
            throw new IOException("Error in constructing AuthRequest from the encoded String ", e);
        } catch (UnmarshallingException e) {
            throw new IOException("Error in constructing AuthRequest from the encoded String ", e);
        }
    }

    public static String marshall(XMLObject xmlObject)
            throws MarshallingException {
        try {
            doBootstrap();
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");

            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString();
        } catch (ClassNotFoundException e) {
            throw new MarshallingException("Error Serializing the SAML Response", e);
        } catch (InstantiationException e) {
            throw new MarshallingException("Error Serializing the SAML Response", e);
        } catch (IllegalAccessException e) {
            throw new MarshallingException("Error Serializing the SAML Response", e);
        }
    }

    public static String encode(String xmlString)
            throws Exception {
        Deflater deflater = new Deflater(8, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);

        deflaterOutputStream.write(xmlString.getBytes());
        deflaterOutputStream.close();

        String encodedRequestMessage = org.opensaml.xml.util.Base64.encodeBytes(byteArrayOutputStream.toByteArray(), 8);

        return encodedRequestMessage.trim();
    }

    public static String decode(String encodedStr)
             throws IOException {

        org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);
            try {
//                Inflater inflater = new Inflater(true);
//                inflater.setInput(base64DecodedByteArray);
//                byte[] xmlMessageBytes = new byte[5000];
//                int resultLength = inflater.inflate(xmlMessageBytes);
//
//                if (!inflater.finished()) {
//                    throw new RuntimeException("didn't allocate enough space to hold decompressed data");
//                }
//
//                inflater.end();
//                return new String(xmlMessageBytes, 0, resultLength, "UTF-8");
                return new String(base64DecodedByteArray);
            } catch (Exception e) {
                ByteArrayInputStream bais = new ByteArrayInputStream(base64DecodedByteArray);

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InflaterInputStream iis = new InflaterInputStream(bais);
                byte[] buf = new byte[1024];
                int count = iis.read(buf);
                while (count != -1) {
                    baos.write(buf, 0, count);
                    count = iis.read(buf);
                }
                iis.close();
                return new String(baos.toByteArray());
            }
    }

    public static boolean validateSignature(Response resp) {
        boolean isSigValid = false;
        try {
            KeyStore keyStore = KeyStore.getInstance(Constants.TYPE_JKS);
            keyStore.load(new FileInputStream(new File(getProperty(Constants.SAML2_SSO_KEY_STORE_PATH))), getProperty(Constants.SAML2_SSO_KEY_STORE_PASSWORD).toCharArray());

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(getProperty(Constants.SAML2_SSO_IDENTITY_ALIAS));

            X509CredentialImpl credentialImpl = new X509CredentialImpl(cert);
            SignatureValidator signatureValidator = new SignatureValidator(credentialImpl);
            signatureValidator.validate(resp.getSignature());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isSigValid;
    }

    public static String getProperty(String propName) {
        if (properties.isEmpty()) {
            initializeProperties();
        }
        return properties.getProperty(propName);
    }

    private static void initializeProperties() {
        properties.put(Constants.SAML2_SSO_ISSUER_ID, PropsUtil.get(Constants.SAML2_SSO_ISSUER_ID));
        properties.put(Constants.SAML2_SSO_IDENTITY_PROVIDER_URL, PropsUtil.get(Constants.SAML2_SSO_IDENTITY_PROVIDER_URL));
        properties.put(Constants.SAML2_SSO_KEY_STORE_PATH, PropsUtil.get(Constants.SAML2_SSO_KEY_STORE_PATH));
        properties.put(Constants.SAML2_SSO_KEY_STORE_PASSWORD, PropsUtil.get(Constants.SAML2_SSO_KEY_STORE_PASSWORD));
        properties.put(Constants.SAML2_SSO_IDENTITY_ALIAS, PropsUtil.get(Constants.SAML2_SSO_IDENTITY_ALIAS));
    }
}
