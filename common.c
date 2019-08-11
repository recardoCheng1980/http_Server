#include "common.h"
#include <openssl/err.h>

BIO *bio_err=0;
static char *pass;

static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);

void load_dh_params(SSL_CTX *ctx,char *file) {
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL) berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (SSL_CTX_set_tmp_dh(ctx,ret)<0) berr_exit("Couldn't set DH parameters");
}

void generate_eph_rsa_key(SSL_CTX *ctx) {
    RSA *rsa;

    rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
    if (!SSL_CTX_set_tmp_rsa(ctx,rsa)) berr_exit("Couldn't set RSA key");
    RSA_free(rsa);
}

/* A simple error and exit routine*/
int err_exit(char *string) {
  fprintf(stderr,"%s\n",string);
  exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char* string) {
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  exit(0);
}

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata) {
  if(num<strlen(pass)+1)
    return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

static void sigpipe_handle(int x){
  printf("sigpipe_handle\n");
}

SSL_CTX *initialize_ctx() {
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      ERR_load_SSL_strings();
      ERR_load_CRYPTO_strings();
      ERR_load_crypto_strings();
      OpenSSL_add_all_algorithms();
      OpenSSL_add_all_ciphers();
      OpenSSL_add_all_digests();

      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE, sigpipe_handle);

    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_file(ctx, "./server.crt", SSL_FILETYPE_PEM))) {
      berr_exit("Can't read certificate file");
    }

    if(!(SSL_CTX_use_PrivateKey_file(ctx, "./server.key", SSL_FILETYPE_PEM))) {
      berr_exit("Can't read key file");
    }

    return ctx;
}

void destroy_ctx(SSL_CTX *ctx) {
  SSL_CTX_free(ctx);
}
