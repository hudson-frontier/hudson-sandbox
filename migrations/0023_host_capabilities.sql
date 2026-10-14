-- Operator compatibility policy remains separate from authenticated observation.
-- NULL preserves legacy hosts; an enrolled host cannot silently omit its contract.
ALTER TABLE hosts ADD COLUMN runtime_capabilities jsonb;
ALTER TABLE hosts ADD COLUMN runtime_capabilities_epoch bigint
    CHECK (runtime_capabilities_epoch IS NULL OR runtime_capabilities_epoch > 0);
