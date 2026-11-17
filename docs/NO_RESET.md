# What changes, and what survives a reboot?

OnnDemand's temporary-root workflow does not require a factory reset or
bootloader unlock. It provides access during the current boot while keeping
the installed boot configuration.

| Item | Behavior |
| --- | --- |
| Temporary root | Ends when the device reboots |
| SSH server process | Stops on reboot; no automatic startup service is installed |
| Runtime protections changed during rooting | Reboot is required to end the rooted state |
| SSH server files, credentials, and host identity | Remain on disk for later setup |
| App, file, or settings changes you make | Can persist after reboot |
| Client private key | Remains on the host computer |

Stopping SSH is not the same as ending temporary root. Reboot the device when
you have finished maintenance and want to return to a normal booted session.

Keeping the original boot configuration is intended to support normal device
behavior and streaming compatibility. It does not guarantee a particular app's
playback quality, validation result, or DRM status.

Permanent rooting, unlocking, flashing, and factory-reset recovery are separate
operations. They are not part of OnnDemand's supported 4K Plus workflow.
A temporary-root session does not make those operations safe or provide a
validated way to reverse them.

For setup and session handling, see the [temporary root guide](ROOT_PATH.md).
For data protection, see [backup and recovery](RESTORE.md).
