# FAQ

### Can I use the data structures multiple times after having initialized them?

Yes, it is possible.
`sv_user_t`, `delegation_t` and `proxy_signature_t` can be used multiple times after having initialized them.  
The same cannot be said for both `sv_public_params_t` and `sv_private_params_t`.  
To avoid memory leaks, they should both be cleared before being used again.  
All the data structures should be cleared when no longer needed.

### How does the `sv_user_t` data structure work?

The `sv_user_t` data structure is used to store the user's data.
It is initialized in a very lazy manner: while all elements are initialized when `user_init()` is called, their value is not updated.
This means that, if either of the user's keys are needed, the appropriate extract function must be called.  
This becomes especially critical when passing the data structure to a function that will use the user's keys.

### How does the precomputation work?

To enable the precomputation, the `public_params_pp()` function must be called after the public parameters have been initialized.
From that moment on, all functions that require the public parameters (nearly all functions in the library) will use the precomputed values instead of computing them on the fly.  
This includes `user_init()`. 
Make sure to call `public_params_pp()` before initializing any user, otherwise the precomputation will not be used and the users will find themselves in an inconsistent state.
