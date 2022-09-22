#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>

#define TEST_USER "testUser"
#define TEST_PASSWORD "TestPassword"

/* Define our service (could really be anything) and then our conversation
   function. */
const char *service="pamtest"; 
extern int converse(int, const struct pam_message **, struct pam_response **, 
        void *);

int main(int argc, char *argv[])
{
    int rval;
    struct pam_conv pconv;
    pam_handle_t *phandle;
    const void *name;

    pconv.conv=&converse;
    pconv.appdata_ptr=NULL;

    /* Call pam_start since you need to before making any other PAM calls */
    if ((rval=pam_start(service,  TEST_USER,
        &pconv, &phandle))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_start: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };
	

    /* Call pam_authenticate it will handle all of our authentication */
    if ((rval=pam_authenticate(phandle, 0))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_authenticate: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };

    /* Call pam_acct_mgmt, we are already authenticated by this routine works out
    if we can actually do what we want to do (e.g. our account may be locked or
    we may not be allowed to do this at this time of day). */
    if ((rval=pam_acct_mgmt(phandle, 0))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_acct_mgmt: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };

    /* The open session is required before we start doing anything. The open
    session functionality is there so that PAM can keep track of what we
    are doing, for example it may record information about the length of
    our session. */
    if ((rval=pam_open_session(phandle, 0))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_open_session: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };

    /* Set our credentials, some environments may require other things to be done
    but hopefully the PAM library implementer has done everything for us */
    if ((rval=pam_setcred(phandle, PAM_ESTABLISH_CRED))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_setcred: %s\n",
            pam_strerror(phandle, rval));
            exit(rval);
    };

    /* Do our something since we're now validated */
    if (pam_get_item(phandle, PAM_USER, &name)==PAM_SUCCESS) {
	    printf("Successfully validated user %s\n",(const char *)name);
    } else {
        fprintf(stderr, "Error: pam_get_item (PAM_USER): %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };

    /* Close the session we opened earlier */
    if ((rval=pam_close_session(phandle, 0))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_close_session: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };

    /* End our PAM work */
    if ((rval=pam_end(phandle, rval))!=PAM_SUCCESS) {
        fprintf(stderr, "Error: pam_end: %s\n",
            pam_strerror(phandle, rval));
        exit(rval);
    };
	return 0;
}

int converse(int num_msg, const struct pam_message **msg, 
        struct pam_response **resp, void *appdata_ptr)
{
    int i,len;

    /* Allocate the response buffers */
    if (num_msg>0) {
        *resp=(struct pam_response *)calloc(sizeof(struct pam_response),num_msg);
        if (*resp==NULL) return PAM_BUF_ERR;
    } else {
        return PAM_CONV_ERR;
        };

    for (i=0; i<num_msg; i++) {
        len=strlen(msg[i]->msg);
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
			/* password */
                resp[i]->resp=strdup(TEST_PASSWORD);
                    break;
            case PAM_PROMPT_ECHO_ON:
			/* user */
                resp[i]->resp=strdup(TEST_USER);
                    break;
            case PAM_ERROR_MSG:
            /* Take into account that we may need to add a \n to the line */
                if (msg[i]->msg[len-1]=='\n') {
                    fprintf(stderr, "%s", msg[i]->msg);
                } else {
                    fprintf(stderr, "%s\n", msg[i]->msg);
                    };
                    break;
            case PAM_TEXT_INFO:
            /* Take into account that we may need to add a \n to the line */
                if (msg[i]->msg[len-1]=='\n') {
                    fprintf(stderr, "%s", msg[i]->msg);
                } else {
                    fprintf(stderr, "%s\n", msg[i]->msg);
                   };
                break;
            default:
                return PAM_CONV_ERR;
            };
        };
        return PAM_SUCCESS;
}
