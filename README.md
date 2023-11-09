# Gnark ZK-SNARK library 

###### tags: `Gnark`

> gnark is a fast zk-SNARK library that offers a high-level API to design circuits. The library is open source and developed under the Apache 2.0 license


## 1. Clone the code

```bash=
git clone this-project-code
```


## 2. Install dependencies

```bash=
go mod download
```

## 3. Project Instruction
```bash=
├── aggregate             //  Aggregate signature
│   ├── bls-tools   //  A toolkit that encapsulates aggregate signing and verification
│   │   ├── aug_scheme_mpl.go
│   │   ├── aug_scheme_mpl_test.go
│   │   ├── bls.go
│   │   ├── bls_test.go
│   │   ├── private_key.go
│   │   ├── private_key_test.go
│   │   ├── public_key.go
│   │   └── util.go
│   ├── bls12377   // The bls12377 library recommended by Ethereum
│   │   ├── README.md
│   │   ├── arithmetic_decl.go
│   │   ├── arithmetic_fallback.go
│   │   ├── arithmetic_x86.s
│   │   ├── bls12_377.go
│   │   ├── bls12_377_test.go
│   │   ├── field_element.go
│   │   ├── field_element_test.go
│   │   ├── fp.go
│   │   ├── fp12.go
│   │   ├── fp2.go
│   │   ├── fp6.go
│   │   ├── fp_test.go
│   │   ├── fr.go
│   │   ├── fr_fallback.go
│   │   ├── fr_test.go
│   │   ├── g1.go
│   │   ├── g1_test.go
│   │   ├── g2.go
│   │   ├── g2_test.go
│   │   ├── glv.go
│   │   ├── glv_test.go
│   │   ├── gt.go
│   │   ├── hash_to_field.go
│   │   ├── isogeny.go
│   │   ├── pairing.go
│   │   ├── pairing_test.go
│   │   ├── swu.go
│   │   ├── utils.go
│   │   ├── wnaf.go
│   │   └── wnaf_test.go
│   ├── main.go
│   └── utils.go
├── bls12377         // Gnark official bls12377 library
│   ├── demo   // Gnark official bls12377 demo
│   │   └── main.go
│   ├── multiple  // Generate multiple pieces of data through the gnark-crypto library to implement the cyclic signature verification of gnark library bls12377
│   │   ├── main.go
│   │   └── utils.go
│   └── signle   // Generate data through gnark-crypto to implement signature verification of gnark bls12377
│       ├── main.go
│       └── utils.go
│   └── aggregate   // Generate data through gnark-crypto to aggregate signature verification of gnark bls12377
│       ├── main.go
│       └── utils.go
├── bls12381  // Generate data through gnark-crypto to implement signature verification of gnark bls12381
│   ├── main.go
│   └── utils.go
├── go.mod
└── go.sum
```

## 4. Run the project
```bahs=
# aggregate verify
cd agrgrgate
go run main.go

# gnark bls12377 verify
cd bls12377/(demo|single|multiple|aggregate)
go run main.go

# gnark bls12381 verify
cd bls12381
go run main.go
```

## Appendix

