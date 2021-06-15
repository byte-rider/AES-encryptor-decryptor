/**
 * AESInterface.java
 * This class handles the collection of input from the user.
 * It should be used in conjunction with AES.java
 *
 * The authors responsible for this are:
 * Sarah Peacock, Peter Groenhout, and George Edwards.
 * It is for the second assignment in 2017's COMP3260 course
 * at the Newcastle Unicersity in NSW, Australia.
 */

import java.util.ArrayList;
import java.util.Scanner;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.io.FileOutputStream;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.File;

public class AESInterface
{
  public static void main (String args[]) throws FileNotFoundException
  {
    ArrayList<int[]> inputs = new ArrayList<int[]>();
    int[] myKey = new int[16];

	if(args.length == 0)
	{
		System.out.println("\nERROR: Incorrect use of command line parameter");
		System.out.println("Correct Usage: java AESInterface <InputFileName>");
		return;
	}

	Scanner input = new Scanner(new FileInputStream(args[0]));
	int encryptFlag = input.nextInt();
	int modeFlag = input.nextInt();
	int transmissionSize = input.nextInt();
	for(int b=0;b<2;b++)
	{
		int[] inBytes = new int[16];
		for(int i=0;i<16;i++)
		{
			inBytes[i] = input.nextInt(16);
		}
		inputs.add(inBytes);
	}

	for(int i=0;i<16;i++)
	{
		myKey[i] = input.nextInt(16);
	}

	int[] IV = new int[16];
	if(modeFlag!=0)
	{
		for(int i=0;i<16;i++)
		{
			IV[i] = input.nextInt(16);
		}
	}
	input.close();

	// Perform actual AES encryption
  AES testAES = new AES(  encryptFlag, modeFlag, transmissionSize, inputs, myKey, IV);
  String output = testAES.go();
  System.out.println("Output: " + output);

	// Create new output file
	PrintWriter outputStream = null;
	String filename = "OutputFile.txt";
	try
  {
		outputStream = new PrintWriter(filename);
	}
	catch(FileNotFoundException e)
  {
		// print error message if file not created correctly and exit program
		System.out.println("Error creating the file " + filename);
		System.exit(0);
	}

	// prepare encryption flag for output file. If encrypt flag is 1, clear to 0. if encrypt flag is 0, set to 1.
	encryptFlag = (encryptFlag + 1) % 2;

	// Output encryptflag, modeFlag, transmissionSize and the paintext to the output file.
	outputStream.println(encryptFlag);
	outputStream.println(modeFlag);
	outputStream.println(transmissionSize);
	outputStream.println(output);


	// Convert key to array of hex values and then to single string.
	String[] hexKeyCopy = new String[16];
	for (int i = 0; i < myKey.length; i++)
  {
		 hexKeyCopy[i] = Integer.toHexString(myKey[i]);
	}
	String outputKey = String.join(" ", hexKeyCopy);

	// Output key to file
	outputStream.println(outputKey);

	// If encryption mode is not 0, convert IV to array of hex values and then to single string for outputIV. If encryption mode is 0, outputIV is 0.
	String outputIV = new String();
	if (modeFlag != 0)
  {
		String[] hexIVCopy = new String[IV.length];
		for (int i = 0; i < IV.length; i++)
    {
			hexIVCopy[i] = Integer.toHexString(IV[i]);
		}
		outputIV = String.join(" ", hexIVCopy);
	}
	else
  {
		outputIV = "0";
	}

	// output IV to file
	outputStream.println(outputIV);
	outputStream.close();
  }
}
