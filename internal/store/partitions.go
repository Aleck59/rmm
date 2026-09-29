package store

import (
	"context"
	"fmt"
)

// PartitionLookaheadDays is how many future daily partitions are kept ready.
const PartitionLookaheadDays = 8

// MaintainPartitions keeps the partitioned tables usable: it makes sure daily
// raw-metric partitions exist for the whole acceptance window
// [today-retentionDays, today+PartitionLookaheadDays], drops raw partitions
// older than the retention period, and keeps monthly audit partitions ready.
// It is idempotent and safe to run often (the server runs it at start-up and
// every few hours).
func (s *Store) MaintainPartitions(ctx context.Context, retentionDays int) error {
	if retentionDays < 1 {
		return fmt.Errorf("retention must be at least 1 day, got %d", retentionDays)
	}
	for _, table := range []string{"metrics_host", "metrics_disk"} {
		if _, err := s.pool.Exec(ctx,
			`SELECT ensure_partitions($1, 'day', current_date - $2::int, $2::int + $3::int + 1)`,
			table, retentionDays, PartitionLookaheadDays); err != nil {
			return fmt.Errorf("ensure %s partitions: %w", table, err)
		}
		if _, err := s.pool.Exec(ctx,
			`SELECT drop_partitions_older_than($1, now() - make_interval(days => $2::int))`,
			table, retentionDays); err != nil {
			return fmt.Errorf("drop old %s partitions: %w", table, err)
		}
	}
	if _, err := s.pool.Exec(ctx, `SELECT ensure_partitions('audit_log', 'month', current_date, 3)`); err != nil {
		return fmt.Errorf("ensure audit_log partitions: %w", err)
	}
	return nil
}
