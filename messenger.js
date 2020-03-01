"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  HMACWithSHA256,
  HMACWithSHA512,
  SHA256,
  SHA512,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  generateECDSA,
  signWithECDSA,
  verifyWithECDSA,
  randomHexString,
  hexStringSlice,
} from "./lib";

/********* Implementation ********/


//from signal specification
const chain_constant = randomHexString(64); //TODO verify that hex string of length 64 contains 32 bytes of info
const max_skip = 256;

function GENERATE_DH(){
  /*Returns a new Diffie-Hellman key pair.*/
  return generateEG();
}
function DH(dh_pair, dh_pub){;
  /*Returns the output from the Diffie-Hellman calculation between the private
  key from the DH key pair dh_pair and the DH public key dh_pub. If the DH
  function rejects invalid public keys, then this function may raise an
  exception which terminates processing.*/
  return computeDH(dh_pair.secretKey, dh_pub);
}
function KDF_RK(rk, dh_out){
  /*
  Returns a pair (32-byte root key, 32-byte chain key) as the output of applying
  a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.
  You may use a variant of HMAC to implement the symmetric key ratchet
  described in 2.2.
  */
  var bytes64 = HMACWithSHA512(rk, dh_out);
  var bytes32_root = hexStringSlice(bytes64, 0,256-1);
  var bytes32_chain = hexStringSlice(bytes64, 256, 512-1);
  return [bytes32_root, bytes32_chain];
}
function KDF_CK(ck){
  /*Returns a pair (32-byte chain key, 32-byte message key) as the output of
  applying a KDF keyed by a 32-byte chain key ck to some constant.*/
  var bytes64 = HMACWithSHA512(ck, chain_constant);
  var bytes32_chain = hexStringSlice(bytes64, 0,256-1);
  var bytes32_message = hexStringSlice(bytes64, 256, 512-1);
  return [bytes32_chain, bytes32_message];
}
function ENCRYPT(mk, plaintext, associated_data){
  /*Returns an AEAD encryption of plaintext with message key mk. The
  associated_data is authenticated but is not included in the ciphertext.
  Because each message key is only used once, the AEAD nonce may handled in
  several ways: fixed to a constant; derived from mk alongside an independent
  AEAD encryption key; derived as an additional output from KDF_CK(); or chosen
  randomly and transmitted.*/
  return encryptWithGCM(mk, plaintext); //TODO add associated_data?
}
function DECRYPT(mk, ciphertext, associated_data){
  return decryptWithGCM(mk, ciphertext); //TODO add associated_data?
}
function HEADER(dh_pair, pn, n){
  return {
    pub: dh_pair.pub,
    previous_chain_length: pn,
    message_number: n
  }
}
function CONCAT(header){
  return JSON.stringify(header);   //TODO is this ok?
}
function RatchetDecrypt(state, header, ciphertext){
    //plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    //if plaintext != None:
    //    return plaintext
    //if header.dh != state.DHr:
    //    SkipMessageKeys(state, header.pn)
    //    DHRatchet(state, header)
    SkipMessageKeys(this.comms, header.message_number)
    var chainkeyderivation = KDF_CK(this.comms.ckr);
    this.conns.ckr = chainkeyderivation[0];
    var messagekey = chainkeyderivation[1];
    this.conns.nr += 1;
    return DECRYPT(messagekey, ciphertext, CONCAT(header));
}
function SkipMessageKeys(state, until){
    if(this.conns.nr + max_skip < until) throw Exception;
    if(this.conns.ckr != null){
      while(this.conns.nr < until){
        var chainkeyderivation = KDF_CK(this.comms.ckr);
        this.conns.ckr = chainkeyderivation[0];
        var messagekey = chainkeyderivation[1];
        this.conns.nr += 1;
      }
    }
}
function TrySkippedMessageKeys(state, header, ciphertext){
  /*
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None
  */
}
function DHRatchet(){
  /*
  state.PN = state.Ns
  state.Ns = 0
  state.Nr = 0
  state.DHr = header.dh
  state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
  state.DHs = GENERATE_DH()
  state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
  */
}



export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
      // the certificate authority DSA public key is used to
      // verify the authenticity and integrity of certificates
      // of other users (see handout and receiveCertificate)

      // you can store data as needed in these objects.
      // Feel free to modify their structure as you see fit.
      this.caPublicKey = certAuthorityPublicKey;
      this.govPublicKey = govPublicKey;
      this.conns = {
        dhs: null,
        dhr: null,
        rk: null,
        cks: null,
        ckr: null,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: {}
      }; // data for each active connection
      this.certs = {}; // certificates of other users
    };

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  generateCertificate(username) {
    throw("not implemented!");
    const certificate = {};
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  receiveCertificate(certificate, signature) {
    throw("not implemented!");
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  sendMessage(name, plaintext) {
    throw("not implemented!");
    const header = {};
    const ciphertext = "";
    return [header, ciphertext];
  }


  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  receiveMessage(name, [header, ciphertext]) {
    throw("not implemented!");
    return plaintext;
  }
};
