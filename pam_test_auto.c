#include <sys/types.h>

#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <pwd.h>
//#include <unistd.h>
//#include <crypt.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>

const char *pCredentials = "sergey:12345";   /* your auth data (need to set up) */


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    struct passwd *pwd;
    /*struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
        
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS)
        return PAM_AUTH_ERR;*/
        
    /* parsing username and password */
    char *pch, user[30], password[30];
    char right[] = "12345";     /* right password */
	pch = strchr(pCredentials, ':');
    if (pch != NULL)
    {
        strncpy(user, pCredentials, pch - pCredentials);
        user[pch - pCredentials] = '\0';
        strcpy(password, pch+1);
    }
    else 
    {
        /*msg.msg_style = PAM_ERROR_MSG;
        msg.msg = "Parsing failed!";
        msgp = &msg;
        
        resp = NULL;
        retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        
        free(resp->resp);
        free(resp);*/
        
        printf("Parsing error!");
        
        return PAM_AUTH_ERR;
    }
    
    /* verifying username */
    pwd = getpwnam(user);
    if (pwd == NULL)
    {
        /*msg.msg_style = PAM_ERROR_MSG;
        msg.msg = "Wrong username!";
        msgp = &msg;
        
        resp = NULL;
        retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        
        free(resp->resp);
        free(resp);*/
        
        printf("Wrong username!");
        
        return PAM_USER_UNKNOWN;
    }
    else
        retval = pam_set_item(pamh, PAM_USER, (const void *)user);
    if (retval != PAM_SUCCESS)
    {
        /*msg.msg_style = PAM_ERROR_MSG;
        msg.msg = "Error with setting item!";
        msgp = &msg;
        
        resp = NULL;
        retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        
        free(resp->resp);
        free(resp);*/
        
        printf("Error with setting item!");
        
        return PAM_AUTH_ERR;
    }

    /* verifying passwords */
    /*char *crypt_password = crypt(password, pwd->pw_passwd);
    if ((crypt_password == NULL) || (strcmp(crypt_password, pwd->pw_passwd) != 0))
    {
        msg.msg_style = PAM_ERROR_MSG;
        msg.msg = "Wrong password!";
        msgp = &msg;
        
        resp = NULL;
        retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        
        free(resp->resp);
        free(resp);
        
        retval = PAM_AUTH_ERR;
    }
    else
        retval = PAM_SUCCESS;*/
    
    if (strcmp(right, password) == 0)
        retval = PAM_SUCCESS;
    else
    {
        /*msg.msg_style = PAM_ERROR_MSG;
        msg.msg = "Wrong password!";
        msgp = &msg;
        
        resp = NULL;
        retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        
        free(resp->resp);
        free(resp);*/
        
        printf("Wrong password!");
        
        retval = PAM_AUTH_ERR;
    }

    return retval;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}


#ifdef PAM_STATIC
struct pam_module _pam_unix_auth_modstruct = {
    "pam_test",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
