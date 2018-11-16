// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

/**
 * Provides access to JPEG functions
 *
 * @author Aymeric Alixe
 */

// QAXH <3 

package io.qaxh.jpeg;

//Import for AppInventor
import com.google.appinventor.components.runtime.Component;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;
import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.common.YaVersion;
import com.google.appinventor.components.runtime.util.ErrorMessages;
import com.google.appinventor.components.runtime.util.YailList;
import com.google.appinventor.components.runtime.errors.YailRuntimeError;

//Import for Jpeg
import org.apache.commons.imaging.ImageReadException;
import org.apache.commons.imaging.ImageWriteException;
import org.apache.commons.imaging.Imaging;
import org.apache.commons.imaging.common.ImageMetadata;
import org.apache.commons.imaging.formats.jpeg.JpegImageMetadata;
import org.apache.commons.imaging.formats.jpeg.exif.ExifRewriter;
import org.apache.commons.imaging.formats.tiff.TiffField;
import org.apache.commons.imaging.formats.tiff.constants.ExifTagConstants;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputDirectory;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputSet;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

//Import for Base64
import org.bouncycastle.util.encoders.Base64;

//Import for Hash
import org.web3j.crypto.Hash;
import org.web3j.protocol.core.methods.response.Web3Sha3;
import org.bouncycastle.util.encoders.Hex;

//Description for appInventor
@DesignerComponent(version =0,
		   description = "A component to manipulate JPEG images.",
		   category = ComponentCategory.EXTENSION,
		   nonVisible = true,
		   iconName = "aiwebres/hash.png")
@UsesLibraries(libraries = "commons-imaging-1.0.jar, " +
	       "crypto-3.3.1-android.jar " +
	       "bcprov-jdk15on-149.jar")
@SimpleObject(external=true)

public class QAXH_Jpeg extends AndroidNonvisibleComponent implements Component {
  private static final String LOG_TAG = "QaxhJpegComponent";
  
  /**
   * Creates a QAXH_jpeg component.
   *
   * @param container container, component will be placed in
   */
  public QAXH_Jpeg(ComponentContainer container)
  {
    super(container.$form());
  }

  /**
   * Get the Metadata contained in USER_COMMENT as String
   *
   * @param path, the path of the file to be read
   * @return Metadata if success to read (can be empty if there is no metadata)
   * @return null if the file doesn't exist or can't be read
   */
  @SimpleFunction(
		  description = "Return the Metadata contained in USER_COMMENT as String")
 public static String getMetadata(String path)
  {
    File jpg = new File(path);
    ImageMetadata metadata = null;
    try
      {
	metadata = Imaging.getMetadata(jpg);
      }
    catch (ImageReadException e)
      {
	return null;
      }
    catch (IOException e)
      {
	return null;
      }
    TiffField field = null;
    if (metadata instanceof JpegImageMetadata)
      {
	final JpegImageMetadata jpegMetadata = (JpegImageMetadata) metadata;
	field = jpegMetadata.findEXIFValueWithExactMatch(ExifTagConstants.EXIF_TAG_USER_COMMENT);
      }
    return field == null ? "" : field.getValueDescription();
  }

  /**
   * Return the Metadata contained in USER_COMMENT as List<String>
   *
   * @param path, path of the file to be read
   * @param separator, separator to split the string read
   * @return Same as getMetadata 
   */
  @SimpleFunction(
		  description = "Return the Metadata contained in USER_COMMENT as List<String>")
  public static YailList getMetadataAsList(String path, String separator)
  {
    String meta = getMetadata(path);
    YailList list = new YailList();
    return meta == null ? null : list.makeList(meta.split(separator));
  }

  /**
   * Create file 'out' or override it, then copy metadata from 'in'
   * and add USER_COMMENT metadata (value)
   *
   * @param in, the path of the input file
   * @param out,  the path of the output file
   * @param value, content of metadata USER_COMMENT
   * @return 0 if metadata was added
   * @return 1 if couldn't open files
   * @return 2 if input img could'nt be read
   * @return 3 if output img couldn't be written
   */
  @SimpleFunction(
		  description = "Create file out or override it, then copy metadata from in and add USER_COMMENT metadata (value)")
  public static int addMetadata(String in, String out, String value)
  {
    try
      {
	File jpegImageFile = new File(in);
	File dst =  new File (out);
	FileOutputStream fos = new FileOutputStream(dst);
	OutputStream os = new BufferedOutputStream(fos);
	final JpegImageMetadata jpegMetadata = (JpegImageMetadata) Imaging.getMetadata(jpegImageFile);;
	TiffOutputSet outputSet = null;
	if (jpegMetadata != null )
	  if (jpegMetadata.getExif() != null)
	    outputSet = jpegMetadata.getExif().getOutputSet();
	if (outputSet == null)
	  outputSet = new TiffOutputSet();
	
	//At this point we have a EXIF directory containing  original tags or empty
	
	final TiffOutputDirectory exifDirectory = outputSet.getOrCreateExifDirectory();
	exifDirectory.removeField(ExifTagConstants.EXIF_TAG_USER_COMMENT);
	exifDirectory.add(ExifTagConstants.EXIF_TAG_USER_COMMENT, value);
	new ExifRewriter().updateExifMetadataLossless(jpegImageFile, os, outputSet);
	return 0;
      }
    catch (ImageWriteException e)
      {
	return 3;
      }
    catch (IOException e)
      {
	return 1;
      }
    catch (ImageReadException e)
      {
	return 2;
      }
  }

  /**
   * Same as addMetadata but take a list as value argument
   *
   * @param in, the path of the input file
   * @param out, the path of the output file
   * @param metadatas, list of metadata to be joined to put in USER_COMMENT metadata
   * @param separator, caracter that will be used to join metadatas
   * @return Same as addMetadata
   */
  @SimpleFunction(
		  description = "Create file out or override it, then copy metadata from in and add USER_COMMENT metadatas (metadatas List joined by separator)")
  public static int addListMetadata(String in, String out, YailList metadatas, String separator)
  {
    String metadata = String.join(separator, metadatas.toStringArray());
    return addMetadata(in, out, metadata);
  }

  /**
   * Remove USER_COMMENT metadata
   *
   * @param in, the path of the input file
   * @param out, the path of the output file
   * @return 0 if metadata was removed
   * @return 1 if couldn't open files
   * @return 2 if input img could'nt be read
   * @return 3 if output img could'nt be written
   */
  @SimpleFunction(
		  description = "Remove USER_COMMENT metadata")
  public static int removeMetadata(String in, String out)
  {
    try
      {
	File jpegImageFile = new File(in);
	File dst =  new File (out);
	FileOutputStream fos = new FileOutputStream(dst);
	OutputStream os = new BufferedOutputStream(fos);
	final JpegImageMetadata jpegMetadata = (JpegImageMetadata) Imaging.getMetadata(jpegImageFile);
	TiffOutputSet outputSet = null;
	if (jpegMetadata != null )
	  if (jpegMetadata.getExif() != null)
	    outputSet = jpegMetadata.getExif().getOutputSet();
	if (outputSet == null)
	  outputSet = new TiffOutputSet();
	
	//At this point we have a EXIF directory containing  original tags or empty
	
	final TiffOutputDirectory exifDirectory = outputSet.getOrCreateExifDirectory();
	exifDirectory.removeField(ExifTagConstants.EXIF_TAG_USER_COMMENT);
	new ExifRewriter().updateExifMetadataLossless(jpegImageFile, os, outputSet);
	return 0;
      }
    catch (ImageWriteException e)
      {
	return 3;
      }
    catch (IOException e)
      {
	return 1;
      }
    catch (ImageReadException e)
      {
	return 2;
      }
  }

  /**
   * Give the keccak hash of a file
   *
   * @param String message, message to hash
   * @return Keccak hash
   * @return null if the file doesn't exist
   */
  @SimpleFunction(
		  description = "Computes the Keccak-256 of the file parameter.")
  public String keccak(String path)
  {
    try
      {
	File file = new File(path);
	FileChannel fileChannel = new RandomAccessFile(file, "r").getChannel();
	MappedByteBuffer buffer = fileChannel.map(FileChannel.MapMode.READ_ONLY, 0, fileChannel.size());
	byte bytes[] = new byte[buffer.remaining()];
	buffer.get(bytes);
	return Hash.sha3String(Hex.toHexString(bytes));
      }
    catch (IOException e)
      {
	return null;
      }
  }

    /**
   * Give the Base64 encoded String of input
   *
   * @param String input, String to be encoded
   */
  @SimpleFunction(
		  description = "Get the Base64 encoded for a String.")
  public String stringToBase64(String input)
  {
    return new String(Base64.encode(input.getBytes()));
  }

  /**
   * Give the Base64 encoded String of input
   *
   * @param String input, String to be encoded
   */
  @SimpleFunction(
		  description = "Get the Base64 encoded for a String.")
  public String base64ToString(String input)
  {
    return new String(Base64.decode(input.getBytes()));
  }
}
