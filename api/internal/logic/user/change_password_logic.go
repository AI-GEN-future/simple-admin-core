package user

import (
	"context"

	"github.com/suyuan32/simple-admin-common/utils/encrypt"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/zeromicro/go-zero/core/errorx"

	"github.com/suyuan32/simple-admin-core/api/internal/svc"
	"github.com/suyuan32/simple-admin-core/api/internal/types"
	"github.com/suyuan32/simple-admin-core/rpc/types/core"

	"github.com/zeromicro/go-zero/core/logx"
)

type ChangePasswordLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewChangePasswordLogic(ctx context.Context, svcCtx *svc.ServiceContext) *ChangePasswordLogic {
	return &ChangePasswordLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *ChangePasswordLogic) ChangePassword(req *types.ChangePasswordReq) (resp *types.BaseMsgResp, err error) {
	userData, err := l.svcCtx.CoreRpc.GetUserById(l.ctx, &core.UUIDReq{Id: l.ctx.Value("userId").(string)})
	if err != nil {
		return nil, err
	}

	oldPassword, err := l.svcCtx.Sm2.Sm2Decrypt(req.OldPassword)
	if err != nil {
		return nil, err
	}
	newPassword, err := l.svcCtx.Sm2.Sm2Decrypt(req.NewPassword)
	if err != nil {
		return nil, err
	}

	if encrypt.BcryptCheck(oldPassword, *userData.Password) {
		result, err := l.svcCtx.CoreRpc.UpdateUser(l.ctx, &core.UserInfo{
			Id:       pointy.GetPointer(l.ctx.Value("userId").(string)),
			Password: pointy.GetPointer(newPassword),
		})
		if err != nil {
			return nil, err
		}

		return &types.BaseMsgResp{Msg: l.svcCtx.Trans.Trans(l.ctx, result.Msg)}, nil
	}

	return nil, errorx.NewCodeInvalidArgumentError("login.wrongPassword")
}
