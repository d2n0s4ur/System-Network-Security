#include "arp_spoof.h"

t_list	*ft_lstnew(t_spoof *content)
{
	t_list	*ret;

	ret = (t_list *)malloc(sizeof(t_list));
	if (!ret)
		return (0);
	memcpy(&(ret->content), content, sizeof(t_spoof));
	ret->next = 0;
	return (ret);
}

void	ft_lstadd(t_list **lst, t_list *node)
{
	t_list	*tmp;

	if (!lst || !node)
		return ;
	if (!(*lst))
	{
		*lst = node;
		return ;
	}
	tmp = *lst;
	while (tmp)
	{
		if (!(tmp->next))
			break ;
		tmp = tmp->next;
	}
	tmp->next = node;
}

void	ft_lstclear(t_list **lst)
{
	t_list	*tmp;

	if (!lst)
		return ;
	while (*lst)
	{
		tmp = (*lst)->next;
		free(*lst);
		*lst = tmp;
	}
}