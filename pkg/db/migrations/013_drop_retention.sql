-- Retention and pruning are handled by Proxmox Backup Server (datastore prune jobs);
-- FallBCK never prunes or deletes on PBS. The per-job retention policy goes, and so
-- does the kubernetes "forget orphaned PVC groups" setting kept inside k8s_config.
ALTER TABLE backup_jobs DROP COLUMN IF EXISTS retention_policy;
UPDATE backup_jobs SET k8s_config = k8s_config #- '{volumes,forget_orphans_after_days}'
 WHERE k8s_config ? 'volumes';
