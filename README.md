# cipher block chaining with ciphertext stealing

## goal
Let's make a class to use a 64 bit block cipher in CBC (cipher block chaining) mode! We'll use ciphertext stealing for our padding strategy. And we'll create simple helper methods to encrypt and decrypt parts of text files easily.

## reading
You may be interested in browsing the wiki pages for [block ciphers](https://en.wikipedia.org/wiki/Block_cipher), block cipher [modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation), CBC with [ciphertext stealing](https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing_encryption_using_a_standard_CBC_interface), and perhaps [Blowfish](https://www.schneier.com/academic/blowfish/).

## what's here
A bunch of support code is already written and tested! The [`Blowfish`](src/Blowfish.java) class implements the Blowfish algorithm. You use it by calling the constructor with an array of bytes for the encryption key. Then you will want to encrypt and decrypt 64 bit blocks (longs). It implements the [`BlockCipher64`](src/BlockCipher64.java) interface with it's encrypt and decrypt methods. [`BlockCipher64`](src/BlockCipher64.java) also contains two static helpers for translating byte arrays to longs and vice versa. The [`BlowfishTestVectors`](src/BlowfishTestVectors.java) helped me verify that our implementation was consistent with the reference implementation. [`CBCEncryption`](src/CBCEncryption.java) needs some work, but contains a lot of the bits and pieces you'll need.

## what's left
  * Read through [`CBCEncryption`](src/CBCEncryption.java), it'll save you time in the long run to know what methods are there and what they do.
  * A few methods need fixin':
    * [`randomIV`](src/CBCEncryption.java#L35)
    * [`maskForFirstNBytes`](src/CBCEncryption.java#L179)
    * [`firstNBytesOfXRestFromY`](src/CBCEncryption.java#L184)
    * [`gatherBase64`](src/CBCEncryption.java#L216)
    * [`breakInto64CharLines`](src/CBCEncryption.java#L227)
  * Now try out some examples to get an idea of what's happening
    * Start with [the](src/CBCEncryption.java#L73) [samples](src/CBCEncryption.java#L99) I wrote to help me figure this out, then try changing something
  * Work out how we should [`decrypt`](src/CBCEncryption.java#L189) an encrypted ciphertext. Use the comments and the [ciphertext stealing](https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing_encryption_using_a_standard_CBC_interface) page. Draw an example (perhaps the two samples), figure out where the bytes ought to go.
  * See if your [`decrypt`](src/CBCEncryption.java#L189) does what you thought it should do in your example. See that it reverses the effect of [`encrypt`](src/CBCEncryption.java#L147).
  * Build [`decryptFileBlowfish`](src/CBCEncryption.java#L273), it's straight forward. It's mostly the same parts used in [`encryptFileBlowfish`](src/CBCEncryption.java#L246), but in reverse (of course).
  * [Play](src/CBCEncryption.java#L52) with it!

### partialBlockSample
```shell
u0xee $ java CBCEncryption partialBlockSample
plaintext = [97, 98, 99, 100, 101, 102, 103, 104, 73, 74, 75, 76, 77, 78, 79, 80, 49, 50]
firstBlock               = [97, 98, 99, 100, 101, 102, 103, 104]
secondBlock              = [73, 74, 75, 76, 77, 78, 79, 80]
firstBlock ^ secondBlock = [40, 40, 40, 40, 40, 40, 40, 56]
ciphertext = [97, 98, 99, 100, 101, 102, 103, 104, 25, 26, 40, 40, 40, 40, 40, 56, 40, 40]
decrypted = [97, 98, 99, 100, 101, 102, 103, 104, 73, 74, 75, 76, 77, 78, 79, 80, 49, 50]
bytesToString(decrypted) = abcdefghIJKLMNOP12
```

### evenBlockSample
```shell
u0xee $ java CBCEncryption evenBlockSample
plaintext = [97, 98, 99, 100, 101, 102, 103, 104, 73, 74, 75, 76, 77, 78, 79, 80]
firstBlock               = [97, 98, 99, 100, 101, 102, 103, 104]
secondBlock              = [73, 74, 75, 76, 77, 78, 79, 80]
firstBlock ^ secondBlock = [40, 40, 40, 40, 40, 40, 40, 56]
ciphertext = [40, 40, 40, 40, 40, 40, 40, 56, 97, 98, 99, 100, 101, 102, 103, 104]
decrypted = [97, 98, 99, 100, 101, 102, 103, 104, 73, 74, 75, 76, 77, 78, 79, 80]
bytesToString(decrypted) = abcdefghIJKLMNOP
```

### fileSample
```
u0xee $ java CBCEncryption fileSample 'secret key!!' ../resources/original.txt
u0xee $ diff -u ../resources/original.txt ../resources/original.txt.secret.txt
--- ../resources/original.txt	2016-07-27 14:50:56.000000000 -0600
+++ ../resources/original.txt.secret.txt	2016-07-27 21:30:43.000000000 -0600
@@ -1,8 +1,8 @@
 Hello Bob,

 I wanted to share a message with you:
-<<<
-My favorite flavor is hazelnut!
+<<< Base64 encoding of 16 round Blowfish in CBC mode with ciphertext stealing. IV:248631d45c56e53d
+6st1XVWoewNKRE4NYCBhBUHD7i0w4w8mZFsV2r67tA==
 >>>
 Wasn't that a great secret?

@@ -10,9 +10,8 @@
 Alice

 P.S.
-<<<
-These letters have been a great distraction.
-I know you are always there to hear what I have to say.
-Write again soon, but not too soon.
-Thanks
+<<< Base64 encoding of 16 round Blowfish in CBC mode with ciphertext stealing. IV:506d10c226ea275b
+2+jlN4WzO3uUK3zOf585bxjs7q3i0ReeM7Mb0HV7GrgS3OCVPvnT7BCgpXBNwg2f
+7UseXZCoZBYmdwxuCdYJ+TEH8y85RmJQeg4O0B8I++YgkteD8P43VSpcDxfojON8
+TDougD/8e5uoTH3o7Jro9lODnrtbw7XEtG7UMFSY40uFRNVQjOsFWWl8exEdYnc=
 >>>
```
```
u0xee $ diff -u ../resources/original.txt ../resources/original.txt.secret.txt.opened.txt
u0xee $
```
