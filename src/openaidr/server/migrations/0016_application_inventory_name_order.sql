-- Inventory listings page by case-insensitive name; index that keyset order so
-- a page reads only its rows instead of sorting the tenant's whole inventory.
-- The key is the first 256 characters (at most 1 KiB), which keeps every entry
-- under the B-tree size limit for any valid name; it must match SORT_KEY in
-- openaidr/server/app_inventory.py.
CREATE INDEX application_inventory_tenant_name
    ON application_inventory (tenant_id, left(lower(name), 256), id);
