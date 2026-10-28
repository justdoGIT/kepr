/* pam_setitems.c — test-only PAM module for tests/pam_e2e.sh.
 *
 * libpam lets only modules set PAM_AUTHTOK / PAM_OLDAUTHTOK, so this one
 * stands in for the module that checked or changed the password: it sets
 * them from KEPR_TEST_AUTHTOK / KEPR_TEST_OLDTOK, which tests/pam_harness.py
 * changes between steps.
 *
 *   cc -shared -fPIC -o pam_setitems.so tests/pam_setitems.c
 */
#include <security/pam_modules.h>
#include <stdlib.h>

static void put(pam_handle_t *h, int item, const char *env)
{
	const char *v = getenv(env);
	if (v && *v)
		pam_set_item(h, item, v);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *h, int f, int argc, const char **argv)
{
	(void)f; (void)argc; (void)argv;
	put(h, PAM_AUTHTOK, "KEPR_TEST_AUTHTOK");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *h, int f, int argc, const char **argv)
{
	(void)h; (void)f; (void)argc; (void)argv;
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *h, int f, int argc, const char **argv)
{
	(void)argc; (void)argv;
	if (f & PAM_PRELIM_CHECK)
		return PAM_SUCCESS;
	put(h, PAM_OLDAUTHTOK, "KEPR_TEST_OLDTOK");
	put(h, PAM_AUTHTOK, "KEPR_TEST_AUTHTOK");
	return PAM_SUCCESS;
}
