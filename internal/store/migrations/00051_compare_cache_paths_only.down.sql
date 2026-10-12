DELETE FROM compare_patch_cache WHERE paths_only;
ALTER TABLE compare_patch_cache DROP COLUMN paths_only;
