package user

import (
	"context"
	"github.com/suyuan32/simple-admin-common/enum/common"
	"github.com/suyuan32/simple-admin-common/i18n"
	"github.com/suyuan32/simple-admin-common/orm/ent/entctx/rolectx"
	"github.com/suyuan32/simple-admin-common/orm/ent/entctx/userctx"
	"github.com/suyuan32/simple-admin-common/utils/jwt"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/suyuan32/simple-admin-core/rpc/types/core"
	"github.com/zeromicro/go-zero/core/errorx"
	"strconv"
	"strings"
	"time"

	"github.com/suyuan32/simple-admin-core/api/internal/svc"
	"github.com/suyuan32/simple-admin-core/api/internal/types"

	"github.com/zeromicro/go-zero/core/logx"
)

type RefreshTokenLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewRefreshTokenLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RefreshTokenLogic {
	return &RefreshTokenLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx}
}

func (l *RefreshTokenLogic) RefreshToken(req *types.RefreshTokenReq) (resp *types.RefreshTokenResp, err error) {
	userId, err := userctx.GetUserIDFromCtx(l.ctx)
	if err != nil {
		return nil, err
	}
	roleCodes, err := rolectx.GetRoleIDFromCtx(l.ctx)
	if err != nil {
		return nil, err
	}

	userData, err := l.svcCtx.CoreRpc.GetUserById(l.ctx, &core.UUIDReq{
		Id: userId,
	})
	if err != nil {
		return nil, err
	}

	if userData.Status != nil && *userData.Status != uint32(common.StatusNormal) {
		return nil, errorx.NewApiUnauthorizedError(i18n.Failed)
	}

	// 将整数切片转换为字符串切片
	positionIdsSlice := make([]string, 0, len(userData.PositionIds))
	for _, num := range userData.PositionIds {
		positionIdsSlice = append(positionIdsSlice, strconv.Itoa(int(num)))
	}
	positionIds := strings.Join(positionIdsSlice, ",")

	roleListByUser, err := l.svcCtx.CoreRpc.GetRoleList(l.ctx, &core.RoleListReq{
		RoleIds: &core.IDsReq{
			Ids: userData.RoleIds,
		},
	})
	if err != nil {
		return nil, err
	}

	remarksMap := make(map[string]struct{})
	for _, v := range roleListByUser.Data {
		remarksMap[v.GetRemark()] = struct{}{}
	}

	// 拼接有权限的区域id
	var regionIdsStr string
	for k := range remarksMap {
		if regionIdsStr != "" {
			regionIdsStr += ","
		}
		regionIdsStr += k
	}

	token, err := jwt.NewJwtToken(l.svcCtx.Config.Auth.AccessSecret, time.Now().Unix(),
		l.svcCtx.Config.Auth.AccessExpire, jwt.WithOption("userId", userId),
		jwt.WithOption("roleId", strings.Join(roleCodes, ",")),
		jwt.WithOption("deptId", userData.DepartmentId),
		jwt.WithOption("positionIds", positionIds),
		jwt.WithOption("regionId", req.RegionId),
		jwt.WithOption("permissionRegionIds", regionIdsStr),
	)
	if err != nil {
		return nil, err
	}

	// add token into database
	expiredAt := time.Now().Add(time.Hour * time.Duration(l.svcCtx.Config.ProjectConf.RefreshTokenPeriod)).UnixMilli()
	_, err = l.svcCtx.CoreRpc.CreateToken(l.ctx, &core.TokenInfo{
		Uuid:      &userId,
		Token:     pointy.GetPointer(token),
		Source:    pointy.GetPointer("core_user_refresh_token"),
		Status:    pointy.GetPointer(uint32(common.StatusNormal)),
		Username:  userData.Username,
		ExpiredAt: pointy.GetPointer(expiredAt),
	})

	return &types.RefreshTokenResp{
		BaseDataInfo: types.BaseDataInfo{Msg: i18n.Success},
		Data:         types.RefreshTokenInfo{Token: token, ExpiredAt: expiredAt},
	}, nil
}
