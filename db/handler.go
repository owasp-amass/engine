package db

import (
	"context"
	"log"
	"time"

	db "github.com/owasp-amass/asset-db"
	dbtype "github.com/owasp-amass/asset-db/types"
	eng "github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/io"
)

type DB struct {
	assetDB *db.AssetDB
}

func NewHandler(db *db.AssetDB) *DB {
	return &DB{
		assetDB: db,
	}
}

// This handler replaces the responses with assets backed by the asset-db.
func (db *DB) DatabaseWriter(nextHandler eng.Handler) eng.Handler {

	return eng.HandlerFunc(func(ctx context.Context, resp *io.Responses, req io.Request) error {

		err := db.handle(ctx, resp, req)
		if err != nil {
			// log, etc.
		}

		return nextHandler.Handle(ctx, resp, req)
	})

}

func (db *DB) Handle(ctx context.Context, resp *io.Responses, req io.Request) error {
	return db.handle(ctx, resp, req)
}

func (db *DB) handle(ctx context.Context, resp *io.Responses, req io.Request) error {
	log.Println("Handling db i/o w/ len(resp): ", len(resp.Elems))
	for _, rs := range resp.Elems {

		var srcAsset *dbtype.Asset
		// query for the source asset
		a, err := db.assetDB.FindByContent(req.SourceAsset(), time.Time{})
		if err != nil || a != nil || len(a) > 0 {
			// FindByContent returns an array of assets, assume the first asset is the one we want
			srcAsset = a[0]
		} else {
			// if we have never seen the source asset, create it.
			srcAsset, err = db.assetDB.Create(nil, "ignored", req.SourceAsset())
			if err != nil {
				log.Println("[ERROR] failed to write asset to db: ", err)
				return err
			}
		}

		// take the response and have it parse out the discovered assets
		rel, toAsset := rs.AssetRelation()
		_, err = db.assetDB.Create(srcAsset, rel, toAsset)
		if err != nil {
			// failed to write asset, log
			// determine method of propagating this up the stack
		}

	}

	return nil
}
