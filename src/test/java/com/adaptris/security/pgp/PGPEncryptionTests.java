package com.adaptris.security.pgp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import com.adaptris.core.MultiPayloadAdaptrisMessage;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.MultiPayloadByteArrayInputParameter;
import com.adaptris.core.common.MultiPayloadStringInputParameter;
import com.adaptris.core.common.MultiPayloadStringOutputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;

public class PGPEncryptionTests extends PGPTests {

  @Test
  public void testEntireWorkflow() throws Exception {
    MultiPayloadAdaptrisMessage message = newMessage();
    message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
    PGPEncryptService encrypt = getEncryptService(true, true);
    encrypt.doService(message);

    message = newMessage(message);
    message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
    PGPDecryptService decrypt = getDecryptService(PASSPHRASE, true);
    decrypt.doService(message);

    assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
  }

  @Test
  public void testWorkflowNonArmored() throws Exception {
    MultiPayloadAdaptrisMessage message = newMessage();
    message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
    PGPEncryptService encrypt = getEncryptService(false, true);
    encrypt.doService(message);

    message = newMessage(message);
    message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
    PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
    decrypt.doService(message);

    assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
  }

  @Test
  public void testWorkflowNoIntegrity() throws Exception {
    MultiPayloadAdaptrisMessage message = newMessage();
    message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
    PGPEncryptService encrypt = getEncryptService(true, false);
    encrypt.doService(message);

    message = newMessage(message);
    message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
    PGPDecryptService decrypt = getDecryptService(PASSPHRASE, true);
    decrypt.doService(message);

    assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
  }

  @Test
  public void testWorkflowNoArmorOrIntegrity() throws Exception {
    MultiPayloadAdaptrisMessage message = newMessage();
    message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
    PGPEncryptService encrypt = getEncryptService(false, false);
    encrypt.doService(message);

    message = newMessage(message);
    message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
    PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
    decrypt.doService(message);

    assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
  }

  @Test
  public void testEncryptionKeyException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage();
      message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
      PGPEncryptService service = getEncryptService(false, false);
      service.setPublicKey(new ConstantDataInputParameter());
      service.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  @Test
  public void testEncryptionDataException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage();
      message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
      PGPEncryptService service = getEncryptService(false, false);
      service.setClearText(new ConstantDataInputParameter());
      service.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  @Test
  public void testDecryptionKeyParameterException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage();
      message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
      PGPDecryptService service = getDecryptService(PASSPHRASE, false);
      service.setPrivateKey(new ConstantDataInputParameter());
      service.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  @Test
  public void testDecryptionWrongKeyException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage();
      message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
      PGPEncryptService encrypt = getEncryptService(true, true);
      encrypt.doService(message);

      message = newMessage(message);
      /* recall setUp to get a new/wrong private key */
      setUp();
      message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
      PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
      MultiPayloadByteArrayInputParameter passParam = new MultiPayloadByteArrayInputParameter();
      passParam.setPayloadId(PASSPHRASE);
      message.addPayload(PASSPHRASE, PASSPHRASE.getBytes());
      decrypt.setPassphrase(passParam);
      decrypt.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  @Test
  public void testDecryptionPassphraseException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage();
      message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
      PGPDecryptService service = getDecryptService(PASSPHRASE, false);
      service.setPassphrase(new ConstantDataInputParameter());
      service.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  @Test
  public void testDecryptionDataException() {
    try {
      MultiPayloadAdaptrisMessage message = newMessage(true);
      message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
      PGPDecryptService service = getDecryptService(PASSPHRASE, false);
      service.setPassphrase(new PayloadStreamInputParameter());
      service.setCipherText(new ConstantDataInputParameter());
      service.doService(message);

      fail();
    } catch (Exception e) {
      /* expected */
    }
  }

  private PGPEncryptService getEncryptService(boolean armor, boolean integrity) {
    PGPEncryptService service = new PGPEncryptService();
    service.setPublicKey(getKeyInput(armor));
    MultiPayloadStringInputParameter clearParam = new MultiPayloadStringInputParameter();
    clearParam.setPayloadId(PAYLOAD_PLAINTEXT);
    service.setClearText(clearParam);
    service.setCipherText(getCipherOutput(armor));
    service.setArmorEncoding(armor);
    service.setIntegrityCheck(integrity);
    return service;
  }

  private PGPDecryptService getDecryptService(String passphrase, boolean armor) {
    PGPDecryptService service = new PGPDecryptService();
    service.setPrivateKey(getKeyInput(armor));
    service.setPassphrase(new ConstantDataInputParameter(passphrase));
    service.setCipherText(getCipherInput(armor));
    MultiPayloadStringOutputParameter plainParam = new MultiPayloadStringOutputParameter();
    plainParam.setPayloadId(PAYLOAD_PLAINTEXT);
    service.setClearText(plainParam);
    return service;
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    return getEncryptService(true, true);
  }

}
