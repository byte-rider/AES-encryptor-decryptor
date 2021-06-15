Files included in this project:

	AESInterface.java
	AES.java

------------------------------------------------------------------------------------------------------

Students responsible:
George Edwards - 3167656

------------------------------------------------------------------------------------------------------

AESInterface:
This class takes input from a file* using a command line parser** and uses the AES class to determine the
corresponding ciphertext for the given plaintext and mode of operation.
The ciphertext is then outputted as text and a file is created which has the opposite encryption flag
and other parameters so that the OutputFile.txt*** can be used as input again without editing.
(i.e. in order to decrypt something that was just encrypted or encrypt something that was decrypted)

AES:
Responsible for the core of the AES algorithm. It receives the input upon
instantiation from the AESInterface class which in turn collects input from
the user. It performs encryption or decryption using one of four cipher blocks
modes.

------------------------------------------------------------------------------------------------------
* The input file should be in the format:

	<Encryption/Decryption Selection>
	<Mode of Operation>
	<Transmission Size>
	<32-Byte Plaintext>
	<16-Byte Key>
	<16-Byte Initialisation Vector>


** The command line parameter used is used when running the class and is in the format of:

	java AESInterface <InputFileName>


*** OutputFile.txt format

	<New Encryption/Decryption Selection>
	<Mode of Operation>
	<Transmission Size>
	<32-Byte Ciphertext>
	<16-Byte Key>
	<16-Byte Initialisation Vector>
