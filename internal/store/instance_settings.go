package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// InstanceSettingAnnouncementBanners is the instance_settings key holding the
// JSON array of announcement banners shown at the top of every page.
const InstanceSettingAnnouncementBanners = "announcement_banners"

// AnnouncementBanner is one instance-wide banner. Instance admins manage the
// full list; every visitor (login page included) sees the enabled ones.
type AnnouncementBanner struct {
	ID              string `json:"id"`
	Message         string `json:"message"`
	BackgroundColor string `json:"background_color"`
	Enabled         bool   `json:"enabled"`
}

// GetInstanceSettingValue returns the raw JSON value for an instance setting,
// or nil when the key has never been written.
func (q *Queries) GetInstanceSettingValue(ctx context.Context, key string) (json.RawMessage, error) {
	row, err := q.db.GetInstanceSetting(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row.Value, nil
}

// SetInstanceSettingValue stores the raw JSON value for an instance setting.
func (q *Queries) SetInstanceSettingValue(ctx context.Context, key string, value json.RawMessage) error {
	if len(value) == 0 {
		value = json.RawMessage(`{}`)
	}
	_, err := q.db.UpsertInstanceSetting(ctx, dbgen.UpsertInstanceSettingParams{Key: key, Value: value})
	return err
}

// ListAnnouncementBanners decodes the stored banner list; missing or invalid
// state yields an empty list, never an error page for visitors.
func (q *Queries) ListAnnouncementBanners(ctx context.Context) ([]AnnouncementBanner, error) {
	raw, err := q.GetInstanceSettingValue(ctx, InstanceSettingAnnouncementBanners)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return []AnnouncementBanner{}, nil
	}
	banners := []AnnouncementBanner{}
	if err := json.Unmarshal(raw, &banners); err != nil {
		return []AnnouncementBanner{}, nil
	}
	return banners, nil
}

// SaveAnnouncementBanners persists the full banner list.
func (q *Queries) SaveAnnouncementBanners(ctx context.Context, banners []AnnouncementBanner) error {
	if banners == nil {
		banners = []AnnouncementBanner{}
	}
	encoded, err := json.Marshal(banners)
	if err != nil {
		return err
	}
	return q.SetInstanceSettingValue(ctx, InstanceSettingAnnouncementBanners, encoded)
}
