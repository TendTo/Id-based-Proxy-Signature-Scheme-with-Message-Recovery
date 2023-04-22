# Singh and Verma’s Scheme

In 2012, [Harendra Singh](https://www.scopus.com/authid/detail.uri?authorId=57213857642) and [Girraj Kumar Verma](https://www.scopus.com/authid/detail.uri?authorId=50462796100) coauthored the paper [ID-based proxy signature scheme with message recovery](https://www.sciencedirect.com/science/article/abs/pii/S0164121211002159).  
In the paper, they propose a framework of an ID-based proxy signature scheme with message recovery, inspired by [Gu and Zhu (2005)](https://www.researchgate.net/publication/220564274_Proxy_signature_scheme_using_self-certified_public_keys).

In 2017 the scheme was revised by Caixue Zhou in their paper [An Improved ID-based Proxy Signature Scheme with Message Recovery](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery).
They noticed a vulnerability in the scheme and proposed a slight variation to the proxy signing and verification algorithms to solve the issue.

## Preliminaries

### Bilinear pairings

Let $G_1$ be a cyclic additive group and $G_T$ be a cyclic multiplicative group of same prime order $q$.
The discrete logarithm problem (**DLP**) is assumed to be hard in both $G_1$ and $G_T$.  
A bilinear pairing $e$ is a map $e : G1 \times G_1 \to G_T$ with the following properties:

- **Bilinear**: For any $P, Q \in G_1$ and $a, b \in Z^*_q$, we have $e(aP, bP) = e(P, P)^{ab}$.
- **Non-degeneracy**: $\exists P, Q \in G_1$ such that $e(P, Q) \ne 1$.
- **Computability**: There is an efficient algorithm to compute $e(P, Q) \forall P, Q \in G_1$.

### Computational Diffie-Hellmen Problem (CDHP)

For $a, b \in Z^*_q$ and given $P, aP, bP \in G_1$, compute $abP \in G_1$.

### Decisional Diffie-Hellmen Problem (DDHP)

For $a, b, c \in Z^*_q$ and given $P, aP, bP, cP \in G_1$, decide whether $c = ab \mod q$.  
Notice that the **DDHP** is easy in $G_1$, since it is possible to use the bilinear pairing to compute $e(aP, bP) = e(P, P)^{ab}$ and check the result against $e(cP, P) = e(P, P)^c$.

### Gap Diffie-Hellmen group (GDH group)

While the **DDHP** is easy in $G_1$, it there are no known algorithms to solve the **CDHP** in $G_1$ in polynomial time.

## Scheme

The ID-based proxy signature scheme with message recovery (**IDPSWM**) consists of the following eight polynomial time algorithms:

- **Setup**: takes as input a security parameter $\lambda$ and outputs the master key, global public key and system parameters params.
- **Extract**: takes as input the master key and an identity $\text{ID} = \{0, 1\}^*$ and outputs the public-secret key pair of the user $(pk_{ID}, sk_{ID})$.
- **DelGen**: takes as input a warrant $m_w$ and the secret key of the user wanting to delegate their signature, $ID_A$. It outputs a delegation $W_{A \to B}$.
- **DelVerify**: takes as input the delegation $W_{A \to B}$, the public key of the user $ID_A$ and uses it to verify whether the delegation is correct.
- **PKGen**: takes as input the delegation $W_{A \to B}$ and the secret key of $ID_B$ to produce a signing key for the proxy signer.
- **PSign**: probabilistic algorithm used by the proxy signer to produce a signature $\delta$ on message $m$ using their signing key.
- **SignVerify/MessageRecovery**: given a signature $\delta$ and the identities of both original and delegated signers $ID_A$ and $ID_B$, the algorithm verifies wether the signature is valid and, if so, outputs the message $m$.
- **ID**: given a proxy signature, this algorithm recovers the identity of the proxy signer.

### Reference

- [ID-based proxy signature scheme with message recovery](https://www.sciencedirect.com/science/article/abs/pii/S0164121211002159)
- [An Improved ID-based Proxy Signature Scheme with Message Recovery](https://www.researchgate.net/publication/283648628_An_Improved_ID-based_Proxy_Signature_Scheme_with_Message_Recovery)
