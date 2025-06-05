package user

import (
	"context"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/suyuan32/simple-admin-common/utils/uuidx"

	"github.com/suyuan32/simple-admin-core/rpc/ent/user"

	"github.com/suyuan32/simple-admin-core/rpc/internal/svc"
	"github.com/suyuan32/simple-admin-core/rpc/internal/utils/dberrorhandler"
	"github.com/suyuan32/simple-admin-core/rpc/types/core"

	"github.com/zeromicro/go-zero/core/logx"
)

type GetUserByUsernameLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetUserByUsernameLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetUserByUsernameLogic {
	return &GetUserByUsernameLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

func (l *GetUserByUsernameLogic) GetUserByUsername(in *core.UsernameReq) (*core.UserInfo, error) {
	result, err := l.svcCtx.DB.User.Query().
		Where(user.IDEQ(uuidx.ParseUUIDString(in.GetUsername()))).
		WithRoles().WithPositions().WithDepartments().
		First(l.ctx)
	if err != nil {
		return nil, dberrorhandler.DefaultEntError(l.Logger, err, in)
	}

	return &core.UserInfo{
		Id:             pointy.GetPointer(result.ID.String()),
		CreatedAt:      pointy.GetPointer(result.CreatedAt.UnixMilli()),
		UpdatedAt:      pointy.GetPointer(result.UpdatedAt.UnixMilli()),
		Nickname:       &result.Nickname,
		Avatar:         &result.Avatar,
		RoleIds:        GetRoleIds(result.Edges.Roles),
		RoleName:       GetRoleNames(result.Edges.Roles),
		RoleCodes:      GetRoleCodes(result.Edges.Roles),
		PositionIds:    GetPositionIds(result.Edges.Positions),
		Mobile:         &result.Mobile,
		Email:          &result.Email,
		Status:         pointy.GetPointer(uint32(result.Status)),
		Username:       &result.Username,
		HomePath:       &result.HomePath,
		Password:       &result.Password,
		Description:    &result.Description,
		DepartmentId:   &result.DepartmentID,
		DepartmentName: &result.Edges.Departments.Name,
	}, nil
}
