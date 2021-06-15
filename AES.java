/**
 * AES.java
 * This class handles the core of the AES algorithm.
 * It should be used in conjunction with AESInterface.java
 *
 * The authors responsible for this are:
 * Sarah Peacock, Peter Groenhout, and George Edwards.
 * It is for the second assignment in 2017's COMP3260 course
 * at the Newcastle Unicersity in NSW, Australia.
 */

import java.util.ArrayList;
import java.util.Arrays;

public class AES
{
  private int Nb = 4;                     // block length divided by 32 (Nb words)
  private int Nk = 4;                     // key length (Nk words)
  private int Nr = 10;                    // Number of rounds
  private boolean encrypting, decrypting; // flags
  private int mode = 0;                    /* 0 = ECB
                                           /  1 = CFB
                                           /  2 = CBC
                                           /  3 = OFB  */
  private int transmissionSize = 0;
  private int[] OFBVector = new int[4 * Nb];
  private int[] IV = new int[4 * Nb];         // used for XOR'ing in CBC mode
  private int[] keysArray = new int[176];     // internal key array
  private ArrayList<int[]> inputs = new ArrayList<int[]>();         // all input blocks
  private ArrayList<int[][]> keys = new ArrayList<int[][]>(Nr + 1); // +1 for initial key

  // sBoxTable is used for looking up the sBox values (sBox = substitution box; a part of AES)
  private int[] sBoxTable =
									{
                  // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
                    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
                    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
                    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
                    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
                    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
                    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
                    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
                    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
                    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
                    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
                    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // f
                  };

  // used for looking up the inverse sBox values
  private int[] sBoxInverseTable =
                {
                // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
                  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //  0
                  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //  1
                  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //  2
                  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //  3
                  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //  4
                  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //  5
                  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //  6
                  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //  7
                  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //  8
                  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //  9
                  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //  a
                  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //  b
                  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //  c
                  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //  d
                  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //  e
                  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //  f
								};

  /* constructor
      the AES object holds in its instance variables all the information
      required to encrypt or decrypt, minus the actual plaintext/ciphertext.
   */
  public AES( int encryptFlag, int modeFlag, int transmissionSize,
              ArrayList<int[]> inputs, int[] key, int[] initIV)
  {
    if (encryptFlag == 0)
    {
      this.encrypting = true;
      this.decrypting = false;
    }
    else
    {
      this.encrypting = false;
      this.decrypting = true;
    }

    this.mode = modeFlag;
    this.transmissionSize = transmissionSize;
    this.inputs = inputs;
    this.IV = initIV.clone();   // this.initIV = initialisationVector;
    initialKeyExpansion(key);   /* this.keysArray, which is an int[] array, gets
                                   populated sequentially with all key values */
    transformKeysArrayIntoArrayList();  /* this.keysArrayList <int[]>, gets
                                           all keys needed for transformation
                                           rounds, formatted appropriately */
  }

  /**
   * go()
   * Performs either encryption or decryption based on the attributes set on
   * instantiation of this object.
   * @return String: either ciphertext or plaintext depending on the input
   */
  public String go()
  {
    /*  outputString will be populated with either the ciphertext (encrypt)
        or the plaintext (decrypt) */
    String outputString = new String();
    int[] outputVector = new int[4 * Nb];
    int[] previousCipher = new int[4 * Nb];

    /* iterate through all input blocks */
    for (int i = 0; i < inputs.size(); i++) // for every block of input
    {
      int[] inputBlock = inputs.get(i); // block of input that will be encrypted or decrypted
      boolean processingFirstBlock = (i == 0);  /* important to know for some
                                                   cipher modes (eg: on first
                                                   run we might need the IV
                                                   (input vector) to process) */
      if (this.encrypting)
      {
        switch (mode)
        {
          case 0:   /* ENCRYPT - ECB */
                    outputVector = encryptECB(inputBlock).clone();
                    break;
          case 1:   /* ENCRYPT - CFB */
                    outputVector = encryptCFB(inputBlock, IV).clone();
                    break;
          case 2:   /* ENCRYPT - CBC */
                    if (processingFirstBlock)
                    {
                      // use the IV
                      outputVector = encryptCBC(inputBlock, IV).clone();
                      // save for chaining
                      previousCipher = outputVector.clone();
                    }
                    else if (!processingFirstBlock)
                    {
                      // use previous ciphertext
                      outputVector = encryptCBC(inputBlock, previousCipher);
                      // save for future rounds
                      previousCipher = outputVector.clone();
                    }
                    break;
          case 3:   /* ENCRYPT - OFB */
                    if (processingFirstBlock)
                    {
                      // use the IV
                      outputVector = encryptOFB(inputBlock, IV).clone();
                    }
                    else if (!processingFirstBlock)
                    {
                      // use previous ciphertext
                      outputVector = encryptOFB(inputBlock, OFBVector);
                    }
                    break;
          default:  break;
        }
      }
      else if (this.decrypting)
      {
        switch (mode)
        {
          case 0:   /* DECRYPT - ECB */
                    outputVector = decryptECB(inputBlock).clone();
                    break;
          case 1:   /* DECRYPT - CFB*/
                    outputVector = decryptCFB(inputBlock, IV).clone();
                    break;
          case 2:   /* DECRYPT - CBC*/
                    if (processingFirstBlock)
                    {
                      // use the IV
                      outputVector = decryptCBC(inputBlock, IV).clone();
                      // save for chaining
                      previousCipher = inputBlock.clone();
                    }
                    else if (!processingFirstBlock)
                    {
                      // use previous ciphertext
                      outputVector = decryptCBC(inputBlock, previousCipher);
                      // save for future rounds
                      previousCipher = inputBlock.clone();
                    }
                    break;
          case 3:   /* DECRYPT - OFB*/
                    if (processingFirstBlock)
                    {
                      // use the IV
                      outputVector = decryptOFB(inputBlock, IV).clone();
                      // save for chaining
                      previousCipher = outputVector.clone();
                    }
                    else if (!processingFirstBlock)
                    {
                      // use previous ciphertext
                      outputVector = decryptOFB(inputBlock, previousCipher);
                      // save for future rounds
                      previousCipher = outputVector.clone();
                    }
                    break;
          default:  break;
        }
      }
      outputString += intsToHex(outputVector);
    }
    return outputString;
  }

  /**
   * encryptECB
   * @param int[] values inside this array will be copied, that copy will be
   *              encrypted with AES
   * @return int[] ciphertext as vector of hexadecimal bytes
   */
  public int[] encryptECB(int[] plainText)
  {
    // nothing special for ECB mode. It's just straight AES
    return AESEncrypt(plainText).clone(); // clone() for deep copy
  }


  /**
   * encryptCFB
   * Encrypt using Cipher Feedback mode with AES
   * @param int[] the plaintext to be encrypted
   * @param int[] input vector used as input to the AES encryptor on initial
   * run. For more infromation on CFB mode please see the wikipedia article
   * here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29
   * @return int[] ciphertext as vector of hexadecimal bytes
   */
  public int[] encryptCFB(int[] plainText, int[] inputVectorOrPrevCipher)
  {
    int[] cipherText = new int[plainText.length]; // will hold ciphertext
  	int[] temp = AESEncrypt(inputVectorOrPrevCipher);  // output of the AES encryption

  	for(int i=0;i<16;i+=transmissionSize)
  	{
  		for(int k=0;k<16-transmissionSize;k++)
  			inputVectorOrPrevCipher[k]=inputVectorOrPrevCipher[k+transmissionSize];
  		for(int j=0;j<transmissionSize;j++)
  		{
  			cipherText[i+j] = plainText[i+j] ^ temp[j];
  			inputVectorOrPrevCipher[16-transmissionSize+j]=cipherText[i+j];
  		}
  		temp=AESEncrypt(inputVectorOrPrevCipher);
  	}
  	return cipherText;
  }

  /**
   * encryptCBC
   * Encrypt using Cipoher Block Chaining mode with AES
   * @param int[] the plaintext to be encrypted
   * @param int[] input vector used to XOR initial plaintext with
   * for more infromation on CBC mode please see the wikipedia article
   * here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
   * @return int[] ciphertext as vector of hexadecimal bytes
   */
  public int[] encryptCBC(int[] plaintext, int[] inputVectorOrPrevCipher)
  {
    int[] aesInput = transformReturnResult(plaintext, inputVectorOrPrevCipher).clone();
    int[] cipherText = AESEncrypt(aesInput).clone();
    return cipherText;
  }

  /**
   * encryptOFB
   * Encrypt using Output Feedback mode with AES
   * @param int[] the plaintext to be encrypted
   * @param int[] input vector used as AES input instead of the plaintext at
   * time = first block.
   * for more infromation on OFB please see this wikipedia page:
   * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29
   * @return int[] resulting ciphertext as vector of hexadecimal bytes
   */
  public int[] encryptOFB(int[] plainText, int[] inputVectorOrOFBVector)
  {
    int[] aesOutput = AESEncrypt(inputVectorOrOFBVector).clone();
    this.OFBVector = aesOutput.clone();  // save for later
    int[] cipherText = transformReturnResult(aesOutput, plainText);
    return cipherText;
  }

  /**
   * decryptECB
   * @param int[] values inside this array will be copied, that copy will be
   *              decrypted with AES
   * @return int[] resulting plaintext as vector of hexadecimal bytes
   */
  public int[] decryptECB(int[] cipherText)
  {
      return AESDecrypt(cipherText).clone();
  }

  /**
   * decryptCFB
   * Decrypt using Cipher Feedback mode with AES
   * @param int[] the plaintext to be encrypted
   * @param int[] input vector used as input to the AES encryptor on initial
   * run. For more infromation on CFB mode please see the wikipedia article
   * here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29
   * @return int[] resulting plaintext as vector of hexadecimal bytes
   */
  public int[] decryptCFB(int[] cipherText, int[] inputVector)
  {
    int[] plainText = new int[Nb*4];
  	int[] temp = AESEncryptFB(inputVector);
  	for(int i=0;i<16;i+=transmissionSize)
  	{
  		for(int k=0;k<16-transmissionSize;k++)
  		{
  			inputVector[k]=inputVector[k+transmissionSize];
  		}
  		for(int j=0;j<transmissionSize;j++)
  		{
  			plainText[i+j] = cipherText[i+j] ^ temp[j];
  			inputVector[16-transmissionSize+j]=cipherText[i+j];
  		}
  		temp=AESEncryptFB(inputVector);
  	}
  	return plainText;
  }

  /**
   * decryptCBC
   * Decrypt using Cipoher Block Chaining mode with AES
   * @param int[] the ciphertext to be decrypted
   * @param int[] input vector used as initial AES input
   * for more infromation on CBC mode please see the wikipedia article
   * here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
   * @return int[] resulting plaintext as vector of hexadecimal bytes
   */
  public int[] decryptCBC(int[] cipherText, int[] inputVectorOrPrevCipher)
  {
    int[] aesOutput = AESDecrypt(cipherText).clone();
    int[] plainText = transformReturnResult(aesOutput, inputVectorOrPrevCipher);
    return plainText;
  }

  /**
   * decryptOFB
   * Decrypt using Output Feedback mode with AES
   * @param int[] the ciphertext to be decrypted
   * @param int[] input vector used as AES input instead of the plaintext at
   * time = first block.
   * for more infromation on CBC mode please see the wikipedia article
   * here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29
   * @return the resulting plaintext as a vector of hexadecimal bytes
   */
  public int[] decryptOFB(int[] cipherText, int[] inputVectorOrOFBVector)
  {
    int[] aesOutput = AESEncryptFB(inputVectorOrOFBVector).clone();
    this.OFBVector = aesOutput.clone();  // save for later
    int[] plainText = transformReturnResult(aesOutput, cipherText).clone();
    return plainText;
  }

  /**
  * AESEncrypt
  * This performs the black box that is AES encryption.
  * If you look at these images:
  * https://upload.wikimedia.org/wikipedia/commons/d/d6/ECB_encryption.svg
  * https://upload.wikimedia.org/wikipedia/commons/9/9d/CFB_encryption.svg
  * https://upload.wikimedia.org/wikipedia/commons/8/80/CBC_encryption.svg
  * https://upload.wikimedia.org/wikipedia/commons/b/b0/OFB_encryption.svg
  * the function in those images labelled "[block cipher decryption]"
  * is what this method is, i.e., it is the standard implementation
  * of AES encryption.
  * @param int[] plaintext as a vector of hex values
  * @return int[] the resulting ciphertext as a vector of hexadecimal bytes
  */
  private int[] AESEncrypt(int[] plainText)
  {
    // state = plainText
    int[][] state = convertTo2D(plainText).clone();

    // cipherText will be outputted
    int[] cipherTextOut = new int[4 * Nb];

    // perform the first round (it's just an XOR transformation)
    transformFirstArg(state, keys.get(0));

    // perform Nr-1 number of rounds. */
    for (int roundIndex = 1; roundIndex < this.Nr; roundIndex++)
    {
      sBox(state);
      shiftRows(state);
      mixColumns(state);
      transformFirstArg(state, keys.get(roundIndex));
    }

    // perform the Nr'th (last) round, sans-mixColumns()
    sBox(state);
    shiftRows(state);
    transformFirstArg(state, keys.get(Nr));

    cipherTextOut = convertTo1D(state).clone();
    return cipherTextOut;
  }

  /**
  * AESDecrypt
  * This performs the black box that is AES decryption.
  * If you look at these images:
  * https://upload.wikimedia.org/wikipedia/commons/e/e6/ECB_decryption.svg
  * https://upload.wikimedia.org/wikipedia/commons/2/2a/CBC_decryption.svg
  * the box in those images labelled "[block cipher decryption]"
  * that box is what this method is, i.e., it is the standard implementation
  * of AES decryption.
  * @param int[] ciphertext as a vector of hex values
  * @return int[] the resulting plaintext as a vector of hexadecimal bytes
  */
  private int[] AESDecrypt(int[] cipherText)
  {
    int[][] state = convertTo2D(cipherText).clone();  // state = cipherText
    int[] plainText = new int[4 * Nb];

    // perform the first round
    transformFirstArg(state, keys.get(Nr));

    // perform all other rounds counting backwards
    for (int roundIndex = this.Nr-1; roundIndex > 0; roundIndex--)
    {
      shiftRowsInverse(state);
      sBoxInverse(state);
      transformFirstArg(state, keys.get(roundIndex));
      mixColumns(state); // false for !encrypt (will use inverse matrix)
    }

    // perform the final round (round 0)
    shiftRowsInverse(state);
    sBoxInverse(state);
    transformFirstArg(state, keys.get(0));

    plainText = convertTo1D(state).clone();
    return plainText;
  }

  /**
   * convertTo2D
   * int[] --> int[][]
   * Takes a vector and permutes its contents into a
   * 2d array as per section 3.4 (page 9) of the AES FIPS
   * document here: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
   * Example:
   * input = [1,2,3,4,5,6,7,8]
   * output = [[1,5]
   *           [2,6]
   *           [3,7]
   *           [4,8]]
   * Note: the columns of the 2D array represent words.
   * @param int[]   input  [1D array input]
   * @return int[][] output [2D array output]
   */
  private int[][] convertTo2D(int[] input)
  {
    int[][] output = new int[4][Nb];
    for (int r = 0; r < 4; r++) // row
    {
      for (int c = 0; c < Nb; c++)  // column
        output[r][c] = input[r + 4*c];
    }
    return output;
  }

  /**
   * convertTo1D
   * int[][] --> int[]
   * Takes a vector and permutes its contents into an array
   * as per section 3.4 (page 9) of the AES FIPS
   * document here: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
   * Example:
   * input = [[1,5]
   *           [2,6]
   *           [3,7]
   *           [4,8]]
   * output = [1,2,3,4,5,6,7,8]
   * Note: the columns of the 2D array represent words.
   * @param int[][] input [2D array input]
   * @return int[] output [1D array output]
   */
  private int[] convertTo1D(int[][] input)
  {
    int[] output = new int[4 * Nb];
    for (int col = 0; col < Nb; col++)
    {
      for (int row = 0; row < 4; row++)
        output[4*col + row] = input[row][col];
    }
    return output;
  }

  private int[] AESEncryptFB(int[] plainText)
  {
    this.encrypting = true;
    int[] result = AESEncrypt(plainText);
    this.encrypting = false;
    return result;
  }

  /**
   * copies the input key into this.keysArray.
   * this.keyarray is much larger than the input key of 16 bytes. This is
   * because we "expand" the key as per AES spec.
   *
   * @param int[] key inputted by initial user textfile
   */
  private void initialKeyExpansion(int[] in)
  {
    // now copy over for inputted key
    for (int i = 0; i < 16; i++)
      this.keysArray[i] = in[i];

    // now perform keyExpansion
    generateKeys();
  }

  /**
  * generateKeys
  * Performs the key expansion on this.keyArray
  */
  private void generateKeys()
  {
    int[] temp = new int[4];  // 4-byte temp variable
    int c = 16;   // the first 16 bytes of the expanded key are simply the
                  // encryption key, i.e., c = 16
    int rConIterator = 1;

    // we need 11 sets of sixteen bytes each for 128-bit mode
    while (c < 176)
    {
      // copy the temp variable over from the last 4-byte block
      for (int i = 0; i < 4; i++)
        temp[i] = keysArray[i + c - 4];

      // every 4 blocks/bytes, do the business:
      if (c % 16 == 0)
      {
        generateKeysCore(temp, rConIterator);
        rConIterator++;
      }

      for (int i = 0; i < 4; i++)
      {
        keysArray[c] = (keysArray[c-16] ^ temp[i]);
        c++;
      }
    }
  }

  /**
  * generateKeysCore
  * performs some core work on key expansion as per AES spec, specifically,
  * it rotates the word, substitutes, then XOR's. For more explanation see
  * the FIPS document here: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  */
  private void generateKeysCore(int[] wordIn, int iterNumber)
  {
    // rotate input eight bits to the left
    rotateWord(wordIn);

    // Apply AES's sBox on all four bytes in the word
    for (int i = 0; i < 4; i++)
      wordIn[i] = sBoxTable[wordIn[i]];

    // for just the first byte, add 2^iterNumber
    wordIn[0] ^= rCon(iterNumber);
  }

  /**
  * transformKeysArrayIntoArrayList
  * takes the expanded array of key values, this.keyArray, and permutes
  * the values into a 4xNb (4x4) grid. One grid represents one 'key' as
  * AES uses lots of 'keys' throughout its process.
  * The values are permutes as follows:
  * from this = [00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,10,11,12,...]
  * to this = {{00,04,08,0C,      {10,14,18,1C
  *             01,05,09,0D,       11,15,19,1D    ... and so on
  *             02,06,0A,0E,       12,16,1A,1E
  *             03,07,0B,0F},      13,17,1B,1F},
  *
  * Each 4x4 key is added to this.keys, an ArrayList of int[][]'s
  */
  private void transformKeysArrayIntoArrayList()
  {
    // now start making key pages into ArrayList
    for (int kpi = 0; kpi < 11; kpi++)  // key-page index. There will be 11 all up
    {
      // make a new 4x4 grid
      int[][] newKeyPage = new int[4][Nb];

      // populate the 4x4 grid, arranging the keys using the columnar
      // transposition method as outlined in the AES doco located
      // here: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
      // See secion 3.4 on page 9 of that document for a nice picture
      for (int r = 0; r < 4; r++)
      {
        for (int c = 0; c < Nb; c++)
          newKeyPage[r][c] = keysArray[kpi*16 + r + 4*c]; // why these values?
                                                        // see comment in parent
                                                        // for loop
      }

      // now save the new key page (will be used by the rounds).
      this.keys.add(newKeyPage);
    }
  }

  /**
   * transformFirstArg
   * XORs each byte within the transformee array
   * by each byte in the transformer array. Note: the
   * results are not returned in a new array but rather
   * the first parameter is modified with the results, hence
   * the method-name "transformFirstArg"
   * @param int[][] transformee [description]
   * @param int[][] transformer [description]
   */
  private void transformFirstArg(int[][] transformee, int[][] transformer)
  {
    for (int row = 0; row < 4; row++)
    {
      for (int column = 0; column < Nb; column++)
        transformee[row][column] ^= transformer[row][column];
    }
  }

  /**
  * transformReturnResult
  * XORs each byte within the transformee array
  * by each byte in the transformer array. Note: the
  * results are returned in a new in[] array, the input
  * parameter arrays remain untouched. In c++ land the parms
  * would be say "const", hence the method name "transformReturnResult"
  */
  private int[] transformReturnResult(int[] transformee, int[] transformer)
  {
    int[] output = transformee.clone();
    for (int i = 0; i < transformee.length; i++)
      output[i] ^= transformer[i];

    return output;
  }

  /**
   * sBox
   * modifies each value of the input array by substituting it in the
   * this.sBox lookup table. These value are part of the AES spec.
   * @param int[][] subMe [description]
   */
  private void sBox(int[][] subMe)
  {
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
        subMe[row][col] = this.sBoxTable[subMe[row][col]];
    }
  }

  /**
   * sBoxInverse
   * modifies each value of the input array by substituting it in the
   * this.sBoxInverseTable lookup table. These values are part of the AES spec.
   * @param int[][] subMe [description]
   */
  private void sBoxInverse(int[][] subMe)
  {
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
        subMe[row][col] = this.sBoxInverseTable[subMe[row][col]];
    }
  }

  /**
   * shiftRows
   * permutes some of the values within the input array
   * by shifting them as per the AES spec. The shifts are as follows:
   * FROM THIS: {{01,02,03,04,
   *              11,12,13,14,
   *              21,22,23,24,
   *              31,32,33,34}}
   *
   * TO THIS:   {{01,02,03,04,
   *              12,13,14,11
   *              23,24,21,22
   *              34,31,32,33}}
   * @param int[][] shiftMe [description]
   */
  private void shiftRows(int[][] shiftMe)
  {
    // first copy all values
    int[][] arrayClone = new int[4][Nb];
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
        arrayClone[row][col] = shiftMe[row][col];
    }

    // now shift
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
        shiftMe[row][col] = arrayClone[row][ (col + row) % Nb ];
    }
  }

  /**
   * shiftRowsInverse
   * permutes some of the values within the input array
   * by shifting them as per the AES spec. The shifts are as follows:
   * FROM THIS: {{01,02,03,04,
   *              12,13,14,11
   *              23,24,21,22
   *              34,31,32,33}}
   *
   * TO THIS:   {{01,02,03,04,
   *              11,12,13,14,
   *              21,22,23,24,
   *              31,32,33,34}}
   *
   * @param int[][] shiftMe [description]
   */
  private void shiftRowsInverse(int[][] shiftMe)
  {
    // first copy all values
    int[][] arrayClone = new int[4][Nb];
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
        arrayClone[row][col] = shiftMe[row][col];
    }

    // now shift
    for (int row = 0; row < 4; row++)
    {
      for (int col = 0; col < Nb; col++)
      {
        int newCol = (((col - row) % Nb) + Nb) % Nb;
        shiftMe[row][col] = arrayClone[row][newCol];
      }
    }
  }

  /**
   * mixColumns
   * Responsible for AES's mix column stage.
   * Mix-column, along with shift row, is how AES performs diffusion.
   *
   * The mix column stage works by taking a single column of four
   * of AES's sixteen values and performing a matrix multiplication
   * in AES's Galois field. This makes it so each byte in the input
   * affects all four bytes of the output.
   * @param int[][] mixMeMatrix [description]
   */
  private void mixColumns(int[][] mixMeMatrix)
  {
    int[] word = new int[Nb];

    // for all words in matrix
    for (int col = 0; col < Nb; col++)
    {
      // for each values in a word
      for (int row = 0; row < 4; row++)
        word[row] = mixMeMatrix[row][col]; // grab value

      // mix word up
      if (this.encrypting)
      {
        mixColumn(word);
      }
	    else if (this.decrypting)
      {
        mixColumnInverse(word);
      }

      // copy out values
      for (int row = 0; row < 4; row++)
        mixMeMatrix[row][col] = word[row];
    }
  }

  /**
  * Responsible for AES's mix column stage.
  * Mix-column, along with shift row, is how AES performs diffusion.
  *
  * The mix column stage works by taking a single column of four
  * of AES's sixteen values and performing a matrix multiplication
  * in AES's Galois field. This makes it so each byte in the input
  * affects all four bytes of the output.
  *
  * @param int[] in [4-byte input word]
  */
  private void mixColumn(int[] word)
  {
    int[] wordCopy = new int[4];

    wordCopy[0] = gMul(word[0],2) ^ gMul(word[3],1) ^ gMul(word[2],1) ^ gMul(word[1],3);
    wordCopy[1] = gMul(word[1],2) ^ gMul(word[0],1) ^ gMul(word[3],1) ^ gMul(word[2],3);
    wordCopy[2] = gMul(word[2],2) ^ gMul(word[1],1) ^ gMul(word[0],1) ^ gMul(word[3],3);
    wordCopy[3] = gMul(word[3],2) ^ gMul(word[2],1) ^ gMul(word[1],1) ^ gMul(word[0],3);

    for (int i = 0; i < 4; i++)
      word[i] = wordCopy[i];
  }

  /**
   * mixColumnInverse
  * Transformation in the Inverse Cipher that is the inverse of
  * mixColumns()
  *
  * @param int[] word [4-byte input word]
  */
  private void mixColumnInverse(int[] word)
  {
    int[] wordCopy = new int[4];

    wordCopy[0] = gMul(word[0],14) ^ gMul(word[3],9) ^ gMul(word[2],13) ^ gMul(word[1],11);
    wordCopy[1] = gMul(word[1],14) ^ gMul(word[0],9) ^ gMul(word[3],13) ^ gMul(word[2],11);
    wordCopy[2] = gMul(word[2],14) ^ gMul(word[1],9) ^ gMul(word[0],13) ^ gMul(word[3],11);
    wordCopy[3] = gMul(word[3],14) ^ gMul(word[2],9) ^ gMul(word[1],13) ^ gMul(word[0],11);

    for (int i = 0; i < 4; i++)
      word[i] = wordCopy[i];
  }

  /**
   * rotateWord
   * [takes a 4-byte word and rotates it 1 byte to the left]
   * eg:  in:  {01,ab,cd,ef}
   *      out: {ab,cd,ef,01}
   * @param int[] wordIn [4-byte input word]
   */
  private void rotateWord(int[] word)
  {
    int saveByteForLater = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = saveByteForLater;
  }

  /**
   * rCon
   * Rcon is what the AES doco calls the exponentiation of 2 to a
   * user-specified value. Note: operation is performed in AES's finite field.
   * (not regular exponentiation. rCon is a part of AES's key expansion.
   */
  private int rCon(int byteIn)
  {
    int byteOut = 1;
    if (byteIn == 0)
      return 0;

    while (byteIn != 1)
    {
      byteOut = gMul(byteOut,2);
      byteIn--;
    }
    return byteOut;
  }

  /**
   * gMul
   * Galois Field multiplication of the two input bytes
   * @param  int a              byte a
   * @param  int b              byte b
   */
  private int gMul(int a, int b)
  {
    int p = 0;  // product of a and b
    boolean highBitWasSetOnA;   // we save this value for later 'cause we check
                                // for it after we've manipulated 'a'
                                // we can't very well check for it AFTER
                                // we've manipulated a.
    for (int i = 0; i < 8; i++)
    {
      if ((b & 1) == 1)   // low bit set on b
        p = ((p ^= a));
      highBitWasSetOnA = ((a & 0x80) == 0x80);
      a = ((a <<= 1));    /* we recorded if highBitWasSetOnA earlier because
                             bit shifted it here */
      if (highBitWasSetOnA)
        a ^= 0x1b;       // a XOR 00011011, i.e., x^8 + x^4 + x^3 + x + 1
      b >>= 1;
    }
    return p % 256;     // result MOD 256 as we want 8-bit result [0-255]
  }

  /**
   * intsToHex
   * Takes an input vector of byte values and outputs a String of hex values.
   * @param  int[] intArray      input vector of bytes
   * @return       String of byte values
   */
  private String intsToHex(int[] intArray)
  {
    String out = new String();
    for (int i = 0; i < intArray.length; i++)
      out += Integer.toHexString(intArray[i])+" ";

    return out;
  }


//
//   /*
//
//
//           HERE BE DEBUGGING HELP
//
//
//
//    */
//
//
//   private void printStateVal(int[][] in, String name)
//   {
//     System.out.println(name + ": ");
//     for (int r = 0; r < in.length; r++)
//     {
//       if (r != 0)
//       {
//         System.out.println(); //new column
//       }
//
//       for (int c = 0; c < in[r].length; c++)
//       {
//         System.out.print("[" + in[r][c] + "]");
//       }
//     }
//     System.out.println();
//   }
//
//   private void printStateHex(int[][] in, String name)
//   {
//     System.out.println(name + ": ");
//     for (int r = 0; r < in.length; r++)
//     {
//       if (r != 0)
//       {
//         System.out.println(); //new column
//       }
//
//       for (int c = 0; c < in[r].length; c++)
//       {
//         System.out.print("[" + Integer.toHexString(in[r][c]) + "]");
//       }
//     }
//     System.out.println();
//   }
//
//   private void printStateHex(int[] in, String name)
//   {
//     System.out.println(name + ": ");
//     for (int i = 1; i < in.length + 1; i++)
//     {
//       System.out.print("[" + Integer.toHexString(in[i-1]) + "]");
//       if (i % 4 == 0)
//       {
//         System.out.println(); //new column
//       }
//     }
//     System.out.println();
//   }
//
//   private void printStateChars(int[][] in, String name)
//   {
//     System.out.println(name + ": ");
//     for (int r = 0; r < in.length; r++)
//     {
//       if (r != 0)
//       {
//         System.out.println(); //new column
//       }
//
//       for (int c = 0; c < in[r].length; c++)
//       {
//         System.out.print("[" + Character.toString((char)in[r][c]) + "]");
//       }
//     }
//     System.out.println();
//   }


}
