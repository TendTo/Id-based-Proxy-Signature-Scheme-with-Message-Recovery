#include "IdSignature.h"

static void main_setup(int sec_lvl, hash_type_t hash_type)
{
    pbc_param_t pairing_p;
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;

    params_init(pairing_p, sec_lvl);
    setup_from_params(public_p, secret_p, sec_lvl, pairing_p);

    pbc_param_out_str(stdout, pairing_p);
    element_printf("hash_type %d\nP %B\npk %B\nmsk %B\n", hash_type, public_p->P, public_p->pk, secret_p->msk);

    secret_param_clear(secret_p);
    public_param_clear(public_p);
    pbc_param_clear(pairing_p);
}

static void main_keygen(char pairing_p_str[], char *ids[], int ids_len)
{
    element_t pk, sk;
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup_from_str(public_p, secret_p, pairing_p_str);

    for (int i = 0; i < ids_len; i++)
    {
        uint8_t identity[IDENTITY_SIZE];
        memset(identity, 0, IDENTITY_SIZE);
        memcpy(identity, ids[i], STR_IDENTITY_SIZE(ids[i]));
        extract_p(pk, identity, public_p);
        extract_s(sk, identity, secret_p);
        element_printf("ID: %s\nPublic key: %B\nPrivate key: %B\n", ids[i], pk, sk);
    }

    element_clear(pk);
    element_clear(sk);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void main_delegate(char pairing_p_str[], char sk_str[], char from[], char to[])
{
    element_t sk;
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    warrant_t m;
    delegation_t w;
    setup_from_str(public_p, secret_p, pairing_p_str);
    element_init_G1(sk, public_p->pairing);
    element_set_str(sk, sk_str, 10);

    memset(m, 0, sizeof(struct warrant_struct));
    memcpy(m->from, from, STR_IDENTITY_SIZE(from));
    memcpy(m->to, to, STR_IDENTITY_SIZE(to));

    delegate(w, sk, m, public_p);
    element_printf("r:\t%B\nS:\t%B\n", w->r, w->S);

    element_clear(sk);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void main_del_verify(char pairing_p_str[], char r_str[], char S_str[], char from[], char to[])
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    warrant_t m;
    delegation_t w;
    setup_from_str(public_p, secret_p, pairing_p_str);
    element_init_GT(w->r, public_p->pairing);
    element_init_G1(w->S, public_p->pairing);
    element_set_str(w->r, r_str, 10);
    element_set_str(w->S, S_str, 10);
    w->m = m;

    memset(m, 0, sizeof(struct warrant_struct));
    memcpy(m->from, from, STR_IDENTITY_SIZE(from));
    memcpy(m->to, to, STR_IDENTITY_SIZE(to));

    int res = del_verify(w, m->from, public_p);
    printf("Is the delegation from '%s' to '%s'? %s\n", from, to, res ? "YES" : "NO");

    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

int main(int argc, char *argv[])
{
    int opt;
    char *op = NULL;
    int sec_lvl = DEFAULT_SEC_LVL, seed = 0;
    hash_type_t hash_type = DEFAULT_HASH_TYPE;
    FILE *stream = NULL, *saved = NULL;

    // Handle inputs
    while ((opt = getopt(argc, argv, ":hl:a:s:f:t:o:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf(HELP_TOOLTIP, argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'l':
            sec_lvl = atoi(optarg);
            break;
        case 'a':
            if (strcmp(optarg, "sha1") == 0)
                hash_type = sha_1;
            else if (strcmp(optarg, "sha256") == 0)
                hash_type = sha_256;
            else if (strcmp(optarg, "sha512") == 0)
                hash_type = sha_512;
            else
            {
                fprintf(stderr, "%s: Invalid hash type: %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            seed = atoi(optarg);
            break;
        case 'o':
            stream = fopen(optarg, "w");
            if (stream == NULL)
            {
                fprintf(stderr, "%s: Could not open file: %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case '?':
            fprintf(stderr, "%s: Unexpected option: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "%s: Missing value for: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, USAGE, argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    PARAMS_ERROR(1, argc - optind, argv);
    op = argv[optind];

    // Random
    if (seed > 0)
        pbc_random_set_deterministic((unsigned int)seed);
    // Redirect output
    if (stream != NULL)
    {
        saved = stdout;
        stdout = stream;
    }

    // Operation parsing
    if (strcmp(op, "setup") == 0)
    {
        main_setup(sec_lvl, hash_type);
    }
    else if (strcmp(op, "keygen") == 0)
    {
        PARAMS_ERROR(3, argc - optind, argv);
        main_keygen(argv[optind + 1], argv + optind + 2, argc - optind - 2);
    }
    else if (strcmp(op, "delegate") == 0)
    {
        PARAMS_ERROR(5, argc - optind, argv);
        main_delegate(argv[optind + 1], argv[optind + 2], argv[optind + 3], argv[optind + 4]);
    }
    else if (strcmp(op, "del_verify") == 0)
    {
        PARAMS_ERROR(6, argc - optind, argv);
        main_del_verify(argv[optind + 1], argv[optind + 2], argv[optind + 3], argv[optind + 4], argv[optind + 5]);
    }

    if (stream != NULL)
    {
        stdout = saved;
        fclose(stream);
    }

    return EXIT_SUCCESS;
}