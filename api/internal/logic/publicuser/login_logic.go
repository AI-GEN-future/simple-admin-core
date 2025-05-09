package publicuser

import (
	"context"
	"github.com/suyuan32/simple-admin-common/config"
	"github.com/suyuan32/simple-admin-common/enum/common"
	"strconv"
	"strings"
	"time"

	"github.com/suyuan32/simple-admin-common/utils/encrypt"
	"github.com/suyuan32/simple-admin-common/utils/jwt"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/zeromicro/go-zero/core/errorx"

	"github.com/suyuan32/simple-admin-core/api/internal/svc"
	"github.com/suyuan32/simple-admin-core/api/internal/types"
	"github.com/suyuan32/simple-admin-core/rpc/types/core"

	"github.com/zeromicro/go-zero/core/logx"
)

type LoginLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewLoginLogic(ctx context.Context, svcCtx *svc.ServiceContext) *LoginLogic {
	return &LoginLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *LoginLogic) Login(req *types.LoginReq) (resp *types.LoginResp, err error) {
	if l.svcCtx.Config.ProjectConf.LoginVerify != "captcha" && l.svcCtx.Config.ProjectConf.LoginVerify != "all" {
		return nil, errorx.NewCodeAbortedError("login.loginTypeForbidden")
	}

	if ok := l.svcCtx.Captcha.Verify(config.RedisCaptchaPrefix+req.CaptchaId, req.Captcha, true); ok {
		user, err := l.svcCtx.CoreRpc.GetUserByUsername(l.ctx,
			&core.UsernameReq{
				Username: req.Username,
			})
		if err != nil {
			return nil, err
		}

		if user.Status != nil && *user.Status != uint32(common.StatusNormal) {
			return nil, errorx.NewCodeInvalidArgumentError("login.userBanned")
		}

		password, err := l.svcCtx.Sm2.Sm2Decrypt(req.Password)
		if err != nil {
			return nil, err
		}

		if !encrypt.BcryptCheck(password, *user.Password) {
			return nil, errorx.NewCodeInvalidArgumentError("login.wrongUsernameOrPassword")
		}
		// 获取 position id
		userData, err := l.svcCtx.CoreRpc.GetUserList(l.ctx, &core.UserListReq{
			UsernameStrict: &req.Username,
		})
		if err != nil {
			return nil, err
		}
		// 将整数切片转换为字符串切片
		var stringSlice []string
		for _, num := range userData.Data[0].PositionIds {
			stringSlice = append(stringSlice, strconv.Itoa(int(num)))
		}
		// 使用 strings.Join 将字符串切片转换为逗号隔开的字符串
		positionIds := strings.Join(stringSlice, ",")

		//fmt.Println(userData.Data[0].PositionIds)
		token, err := jwt.NewJwtToken(l.svcCtx.Config.Auth.AccessSecret, time.Now().Unix(),
			l.svcCtx.Config.Auth.AccessExpire, jwt.WithOption("userId", user.Id), jwt.WithOption("roleId",
				strings.Join(user.RoleCodes, ",")), jwt.WithOption("deptId", user.DepartmentId),
			jwt.WithOption("regionId", req.RegionId), jwt.WithOption("positionIds", positionIds))
		if err != nil {
			return nil, err
		}

		// add token into database
		expiredAt := time.Now().Add(time.Second * time.Duration(l.svcCtx.Config.Auth.AccessExpire)).UnixMilli()
		_, err = l.svcCtx.CoreRpc.CreateToken(l.ctx, &core.TokenInfo{
			Uuid:      user.Id,
			Token:     pointy.GetPointer(token),
			Source:    pointy.GetPointer("core_user"),
			Status:    pointy.GetPointer(uint32(common.StatusNormal)),
			Username:  user.Username,
			ExpiredAt: pointy.GetPointer(expiredAt),
		})

		if err != nil {
			return nil, err
		}

		err = l.svcCtx.Redis.Del(l.ctx, config.RedisCaptchaPrefix+req.CaptchaId).Err()
		if err != nil {
			logx.Errorw("failed to delete captcha in redis", logx.Field("detail", err))
		}

		resp = &types.LoginResp{
			BaseDataInfo: types.BaseDataInfo{Msg: l.svcCtx.Trans.Trans(l.ctx, "login.loginSuccessTitle")},
			Data: types.LoginInfo{
				UserId: *user.Id,
				Token:  token,
				Expire: uint64(expiredAt),
			},
		}
		return resp, nil
	} else {
		return nil, errorx.NewCodeInvalidArgumentError("login.wrongCaptcha")
	}
}
