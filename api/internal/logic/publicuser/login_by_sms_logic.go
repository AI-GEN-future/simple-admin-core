package publicuser

import (
	"context"
	"github.com/suyuan32/simple-admin-common/config"
	"github.com/suyuan32/simple-admin-common/enum/common"
	"github.com/suyuan32/simple-admin-common/i18n"
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

type LoginBySmsLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewLoginBySmsLogic(ctx context.Context, svcCtx *svc.ServiceContext) *LoginBySmsLogic {
	return &LoginBySmsLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx}
}

func (l *LoginBySmsLogic) LoginBySms(req *types.LoginBySmsReq) (resp *types.LoginResp, err error) {
	if l.svcCtx.Config.ProjectConf.LoginVerify != "sms" && l.svcCtx.Config.ProjectConf.LoginVerify != "sms_or_email" &&
		l.svcCtx.Config.ProjectConf.LoginVerify != "all" {
		return nil, errorx.NewCodeAbortedError("login.loginTypeForbidden")
	}

	captchaData, err := l.svcCtx.Redis.Get(l.ctx, config.RedisCaptchaPrefix+req.PhoneNumber).Result()
	if err != nil {
		logx.Errorw("failed to get captcha data in redis for email validation", logx.Field("detail", err),
			logx.Field("data", req))
		return nil, errorx.NewCodeInvalidArgumentError(i18n.Failed)
	}

	if captchaData != req.Captcha {
		return nil, errorx.NewCodeInvalidArgumentError("login.wrongCaptcha")
	}

	userData, err := l.svcCtx.CoreRpc.GetUserList(l.ctx, &core.UserListReq{
		Page:     1,
		PageSize: 1,
		Mobile:   &req.PhoneNumber,
	})
	if err != nil {
		return nil, err
	}

	if userData.Total == 0 {
		return nil, errorx.NewCodeInvalidArgumentError("login.userNotExist")
	}

	if *userData.Data[0].Status != uint32(common.StatusNormal) {
		return nil, errorx.NewCodeInvalidArgumentError("login.userBanned")
	}

	// 将整数切片转换为字符串切片
	positionIdsSlice := make([]string, 0, len(userData.Data[0].PositionIds))
	for _, num := range userData.Data[0].PositionIds {
		positionIdsSlice = append(positionIdsSlice, strconv.Itoa(int(num)))
	}
	// 使用 strings.Join 将字符串切片转换为逗号隔开的字符串
	positionIds := strings.Join(positionIdsSlice, ",")

	roleListByUser, err := l.svcCtx.CoreRpc.GetRoleList(l.ctx, &core.RoleListReq{
		RoleIds: &core.IDsReq{
			Ids: userData.Data[0].RoleIds,
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
		l.svcCtx.Config.Auth.AccessExpire,
		jwt.WithOption("userId", userData.Data[0].Id),
		jwt.WithOption("roleId", strings.Join(userData.Data[0].RoleCodes, ",")),
		jwt.WithOption("deptId", userData.Data[0].DepartmentId),
		jwt.WithOption("regionId", req.RegionId),
		jwt.WithOption("positionIds", positionIds),
		jwt.WithOption("permissionRegionIds", regionIdsStr),
	)
	if err != nil {
		return nil, err
	}

	// add token into database
	expiredAt := time.Now().Add(time.Second * time.Duration(l.svcCtx.Config.Auth.AccessExpire)).UnixMilli()
	_, err = l.svcCtx.CoreRpc.CreateToken(l.ctx, &core.TokenInfo{
		Uuid:      userData.Data[0].Id,
		Token:     pointy.GetPointer(token),
		Source:    pointy.GetPointer("core_user"),
		Status:    pointy.GetPointer(uint32(common.StatusNormal)),
		Username:  userData.Data[0].Username,
		ExpiredAt: pointy.GetPointer(expiredAt),
	})

	if err != nil {
		return nil, err
	}

	err = l.svcCtx.Redis.Del(l.ctx, config.RedisCaptchaPrefix+req.PhoneNumber).Err()
	if err != nil {
		logx.Errorw("failed to delete captcha in redis", logx.Field("detail", err))
	}

	resp = &types.LoginResp{
		BaseDataInfo: types.BaseDataInfo{Msg: l.svcCtx.Trans.Trans(l.ctx, "login.loginSuccessTitle")},
		Data: types.LoginInfo{
			UserId: *userData.Data[0].Id,
			Token:  token,
			Expire: uint64(expiredAt),
		},
	}
	return resp, nil
}
