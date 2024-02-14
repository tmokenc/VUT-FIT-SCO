#import "@preview/polylux:0.3.1": *
#import themes.university: *

#show: university-theme.with(
  short-author: "Le Duy Nguyen - xnguye27",
  short-title: "Implementation ChaCha20-Poly1305",
  short-date: "20/11/2023",
)

#title-slide(
  authors: ("Le Duy Nguyen"),
  title: "ChaCha20 Implementation",
  subtitle: "Focus on Security",
  date: "20/11/2023",
  institution-name: "Faculty of Information Technology\nBrno University of Technology",
)

#slide(title: [ChaCha20])[
  - Developed by #underline[Daniel J. Bernstein] in 2008
  - *Stream cipher* with #underline[256-bit key] and #underline[96-bit nonce]
  - Recommended by the #underline[Czech National Cyber and Information Security Agency] (NÚKIB)

  #figure(
    image("./chacha20scheme.png", height: 50%),
    caption: [ChaCha20's Scheme]
  )
]

#slide(title: [Technology])[
  #side-by-side[
    - Programming language: *Rust*

    - Architecture: *x86* family
  ][
    #figure(
      image("./rust-logo-blk.svg", width: 60%),
    )
  ]

  - *Github*: #link("https://github.com/tmokenc/VUT-FIT-SCO")
]

#slide(title: [Secure Implementation Guideline], new-section: [VUT FIT])[
  #list-one-by-one(marker: [--], tight: false)[Sensitive functions *must* have time complexity of $O(1)$
    - Operations like #text(orange)[`Divide`, `Modulo`, `If`] introduce variable time complexity.
    #rect(fill: red)[`x = if s { a } else { b }`]
    #rect(fill: lime)[`x = b & ((-(s & 1)) & (a ^ b))`]
  ][*Clean up* data when no longer needed][Minimal dependencies][Testing!]
]

#slide(title: [Problem with Rust])[
  Rust is *too smart* for us crypto-developers

  \
  #side-by-side[
    #underline[What we want]

    ```rs
    let mut key = [1, 2, 3];
    
    do_something_with_key(&key);
    key = [0, 0, 0]; // clean up
    ```
  ][
    #underline[What Rust actually does]

    ```rs
    let mut key = [1, 2, 3];
    
    do_something_with_key(&key);
    // key = [0, 0, 0]; clean up
    ```
    $arrow.t.filled$ _"Bro! You have *deadcode* here.\ I removed it for you. No need to thank me."_
  ]
]

#slide(title: [Problem with Rust 2])[
  Rust is *too smart* for us crypto-developers

  \
  #side-by-side[
    Remember this trick?
    #rect(fill: red)[`x = if s { a } else { b }`]
    #rect(fill: lime)[`x = b & ((-(s & 1)) & (a ^ b))`]
  ][
    #underline[They are the same in x86 assembly]

    ```asm
    test   dil,dil
    jne    8   ; conditional jump
    mov    sil,dl
    mov    eax,esi
    ret    
    ```
  ]

  \
  $arrow.r.curve$ Solution: `core::hint::black_box`
]

#slide(title: [ChaCha20: Usage])[
  #side-by-side[
    #underline[Input]
      - Message *or* Ciphertext
      - 256-bit Key + 96-bit Nonce
  ][
    #underline[Output]
      - Ciphertext *or* Message
  ]

  ```rs
  use chacha20poly1305::ChaCha20;
  let message = b"Your message or cipher text";
  let (key, nonce) = cryptographic_rng();
  let mut cipher = ChaCha20::new(key, nonce);
  match cipher.perform(message) {
    Ok(ciphertext) => // Success
    Err(_) => // The data is too long
  }
  ```
]


#focus-slide()[
  *ChaCha20-Poly1305* \ AEAD Construction
]

#slide(title: [AEAD Construction])[
  - _*A*_\uthenticated _*E*_\ncryption with _*A*_\ssociated _*D*_\ata
    - ChaCha20 provides *confidentiality* and *authentication*
    - what about *integrity*?

  - *Poly1305* - MAC function
    - developed by the same author, Daniel J. Bernstein
    - works *seamlessly* with ChaCha20

  - Recommended by the #underline[Czech National Cyber and Information Security Agency] (NÚKIB)
  - *ChaCha20-Poly1305* is used in various applications, including #underline[OpenSSH] and #underline[TLS 1.3]
]

#slide(title: [AEAD Construction: Scheme])[
  #figure(
    image("ChaCha20-Poly1305_Encryption.svg", height: 90%),
    caption: [ChaCha20-Poly1305 AEAD construct.],
  )
]


#slide(title: [Usage: Encryption])[
  #side-by-side[
    #underline[Input]
      - Message
      - 256-bit Key + 96-bit Nonce
      - AAD
  ][
    #underline[Output]
      - Ciphertext
      - Authentication Tag
  ]

    ```rs
    use chacha20poly1305::ChaCha20Poly1305;
    let message = b"Your message";
    let (key, nonce, aad) = cryptographic_rng();
    let cipher = ChaCha20Poly1305::new(key, nonce, aad);
    match cipher.encrypt_oneshot(message) {
        Ok((ciphertext, tag)) => // Succesfully
        Err(_) => // Something went wrong
    #}
    ```
]

#slide(title: [Usage: Decryption])[
  #side-by-side[
    #underline[Input]
      - Message + Authentication Tag
      - 256-bit Key + 96-bit Nonce
      - AAD
  ][
    #underline[Output]
      - Authenticated Message
  ]

  ```rs
  use chacha20poly1305::ChaCha20Poly1305;
  let (key, nonce, aad, ciphertext, tag) = receive();
  let cipher = ChaCha20Poly1305::new(aad, key, nonce);
  match cipher.decrypt_oneshot(ciphertext, tag) {
    Ok(authenticated_message) => // Success
    Err(why) => // Something wrong with the message
  }
  ```
]

#slide(title: [Limitation])[
  - Limited to encrypting messages up to *256 GiB* in size.
  \
  \
  #figure(
    image("limit.png", width: 80%)
  )
]


#slide(title: [Security Analysis])[
    #side-by-side[
    - #underline[Timing Attack] \
      The execution time is $O(n)$ where $n$ is the length of message \
      $arrow.r.curve$ have #text(green)[better luck] with brute-force

    - #underline[Power Analysis] \
      $arrow.r.curve$ _Unfortunately_, the current implementation is #text(red)[vulnerable] to power analysis
    ][
      #figure(
        image("bench.png"),
        caption: [Execution time / message's length]
      )
    ]
]

#focus-slide()[
  *Thank you for your attention.*
]

#slide(title: [Sources])[
  - https://github.com/tmokenc/VUT-FIT-SCO
  \
  - https://en.wikipedia.org/wiki/ChaCha20-Poly1305
  - https://datatracker.ietf.org/doc/html/rfc8439
]
