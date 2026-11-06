-- Browser invitations preserve the existing verified Google identity binding.
ALTER TABLE platform_admins ADD COLUMN invited_by uuid REFERENCES platform_admins(id) ON DELETE SET NULL;
ALTER TABLE platform_admins ADD COLUMN invitation_key uuid UNIQUE;
