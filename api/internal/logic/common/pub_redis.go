package common

import (
	"context"
	"fmt"
	rediswatcher "github.com/casbin/redis-watcher/v2"
	"github.com/suyuan32/simple-admin-common/config"
	"github.com/suyuan32/simple-admin-core/api/internal/svc"
	"github.com/zeromicro/go-zero/core/logx"
)

type PubRedisLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewPubRedisLogic(ctx context.Context, svcCtx *svc.ServiceContext) *PubRedisLogic {
	return &PubRedisLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *PubRedisLogic) NotifyReloadCasbin() {
	l.svcCtx.Redis.Publish(
		l.ctx, fmt.Sprintf("%s-%d",
			config.RedisCasbinChannel,
			l.svcCtx.Config.RedisConf.Db,
		),
		rediswatcher.Update,
	)
}
