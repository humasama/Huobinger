#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <assert.h>

#include "hipac.h"
#include "psio.h"

#define COMPRESS
//#define DEBUG
//#define TRAVERSE

int rule_num;


void init (struct rlp *root)
{
	int dim = 0;
	//printf ("please input the rule number : ");
	//scanf ("%d", &rule_num);
	rule_num = 6;

	struct rlp *tmp = root;
	tmp->rangeArray = root->rangeArray;

	if (tmp == NULL || tmp->rangeArray == NULL) {
		printf ("init: malloc fail.\n");
		exit(0);
	}

#ifndef COMPRESS
	int dim = 0;
	while ( dim < DIM_NUM ) {
		tmp->rangeArray[1].count = 0;
		tmp->rangeArray[1].g = MAX_EDGE;
		tmp->rangeArray[1].action = FORWARD;	//DEF_ACT;
		tmp->rangeArray[1].dim = dim;
		tmp->rangeArray[1].prior = DEF_PRIOR;
		tmp->tail = 1;
		if ( dim == DIM_NUM-1 ) {
			tmp->leaf = '1';
			tmp->rangeArray[1].child = NULL;
		}
		else {
			tmp->leaf = '0';
			tmp->rangeArray[1].child =  (struct rlp *) malloc (sizeof(struct rlp));
			tmp = tmp->rangeArray[1].child;
			tmp->rangeArray = (struct rlp_range *) malloc (sizeof(struct rlp_range) * 2);
		}
		dim++;
	}
#else
	tmp->rangeArray[1].count = 0;
	tmp->rangeArray[1].g = MAX_EDGE;
	tmp->rangeArray[1].action =	FORWARD;	//DEF_ACT;
	tmp->rangeArray[1].dim = dim;
	tmp->rangeArray[1].prior = DEF_PRIOR;
	tmp->tail = 1;
	tmp->leaf = '0';
	tmp->rangeArray[1].child = NULL;
#endif
}


int locate (unsigned int key, struct rlp *cur_rlp, int *index)	
//binary search to locate the position
{
	 if ( cur_rlp != NULL ) { 
		int l = 1, r = cur_rlp->tail, ptr, mid = (l + r) / 2;
		struct rlp_range *array = cur_rlp->rangeArray;
		while (l <= r) {
			if (array[mid].g < key) {
				l = mid +1;
				mid = (l + r) / 2;
			}
			else if (array[mid].g > key) {
				if (mid == 1) {
					(*index) = 1;
					return 1;
				}
				ptr = mid - 1;
				while (ptr >= 1) {
					if (array[ptr].g > key) ptr--;
					else if (array[ptr].g < key) {
						(*index) = ptr +1;
						return 1;
					}
					else {
						(*index) = ptr;
						return 1;
					}
					
					if (ptr == 0) {
						(*index) = 1;
						return 1;
					}		
				}
			}
			else {
				(*index) = mid;			
				return 1;
			}	
		}	
	 	printf ("locate : cur_rlp is NULL. \n");
	 	return 0;
	}
}

int MRLP_search (unsigned int *fields, struct rlp *root) //return action
{
        struct rlp *ptr = root;
        struct rlp_range *array;
        int cur_dim = 0, action, index = 0;

        if ( ptr != NULL ) {
		array = ptr->rangeArray;
                while (cur_dim < DIM_NUM) {
//struct rlp *l;
                        
                        index =rlp_search (fields, cur_dim, ptr);
                        if (index == 0) {
                                printf ("search fail. \n");
				exit (0);
                        }
#ifdef COMPRESS
			if (array[index].count == 0) return FORWARD; //equal to :array[index].child == NULL, DEF_ACT == FORWARD
#endif		

			if (cur_dim != DIM_NUM-1) {
                        	ptr = array[index].child;
				array = ptr->rangeArray;
			}
                        cur_dim ++;
                }
		return array[index].action;
        }               
        else {
                printf ("MRLP_search : root is NULL !\n");
		exit(0);
        }
}


int rlp_search (unsigned int *fields, int cur_dim, struct rlp *cur_rlp)
{
        if ( cur_rlp != NULL && fields != NULL ) {
		unsigned int key = fields[cur_dim];
		int index;
                struct rlp_range *tmp = cur_rlp->rangeArray;
		locate (key, cur_rlp, &index);
		return index;
	}	

        printf( "rlp_search : rlp is NULL! \n" );
        return 0;
}

void rlp_clone (struct rlp * cur_rlp, struct rlp **l)
{
	if (cur_rlp != NULL) {
		struct rlp_range *tmp_range = cur_rlp->rangeArray;
		struct rlp *clone = (struct rlp *) malloc (sizeof(struct rlp));
		
		if (clone == NULL) {
			printf("rlp_clone: malloc fail.\n");
			exit (0);
		}

		clone->leaf = cur_rlp->leaf;
		clone->tail = cur_rlp->tail;	
		struct rlp_range *clone_range = (struct rlp_range *) malloc (sizeof(struct rlp_range) * (cur_rlp->tail + 1));
#ifdef DEBUG
		if (clone_range == NULL) {
			printf ("rlp_clone: malloc fail.\n");
			exit(0);
		}
#endif

		clone->rangeArray = clone_range;
		int i = 1, end = cur_rlp->tail;		

		while (i <= end) {
			clone_range[i].action = tmp_range[i].action;
			clone_range[i].g = tmp_range[i].g;
			clone_range[i].count = tmp_range[i].count;	
			clone_range[i].dim = tmp_range[i].dim;
			clone_range[i].prior = tmp_range[i].prior;
			clone_range[i].child = tmp_range[i].child; //light copy, meaningless
			i ++;
		}

		(*l) = clone;
		return;
	}
	printf("rlp_clone: cur_rlp is NULL!\n");
	exit (0);
}


void MRLP_clone (struct rlp *cur_rlp,struct rlp **l)
{
	if (cur_rlp == NULL) {
		printf ("MRLP_clone: cur_rlp is NULL.\n");
		return ;
	}
	struct rlp *clone;
       	rlp_clone (cur_rlp, &clone);
	struct rlp_range *array = cur_rlp->rangeArray;
	

#ifdef DEBUG
	if (clone == NULL || clone->rangeArray == NULL) {
		printf ("MRLP_clone fail.\n");
		exit (0);
	}
#endif

	int i = 1, end = cur_rlp->tail;

	if (clone->leaf == '0') {

		while (i <= end) {

			if (array[i].child == NULL) clone->rangeArray[i].child = NULL;
			else MRLP_clone (array[i].child, &clone->rangeArray[i].child);
			i ++;
		}
	}
	
	(*l) = clone;
}

void build_empty_tree (struct rlp **l, int insert_dim)
{
	int layer = insert_dim;
	struct rlp *tmp = (struct rlp *)malloc(sizeof(struct rlp));
	tmp->rangeArray = (struct rlp_range *)malloc(sizeof(struct rlp_range) * 2);
	(*l) = tmp;

	while (layer < DIM_NUM) {
                tmp->rangeArray[1].count = 0;
                tmp->rangeArray[1].g = MAX_EDGE;
                tmp->rangeArray[1].action =	FORWARD;	//DEF_ACT;
                tmp->rangeArray[1].dim = layer;
                tmp->rangeArray[1].prior = DEF_PRIOR;
                tmp->tail = 1;

                if (layer == DIM_NUM - 1) {
                        tmp->leaf = '1';
                        tmp->rangeArray[1].child = NULL;
                }
                else {
                        tmp->leaf = '0';
                        tmp->rangeArray[1].child =  (struct rlp *) malloc (sizeof(struct rlp));
                        tmp = tmp->rangeArray[1].child;
                        tmp->rangeArray = (struct rlp_range *) malloc (sizeof(struct rlp_range) * 2);
#ifdef DEBUG
                        assert (tmp);
                        assert (tmp->rangeArray);
#endif
                }

                layer ++;
	}

}


int rlp_insert (struct rlp *cur_rlp, unsigned int new_g, struct rlp *new_child, int dim, int new_count, int new_action, int new_prior)
{
	if (cur_rlp != NULL) {
		struct rlp_range *array = cur_rlp->rangeArray;
		
		/*look for the location*/
		int index;
		locate(new_g, cur_rlp, &index);
		if (index == 0) {
			printf ("rlp insert fail.\n");
			return 0;
		}
		if (array[index].g == new_g ) {
			printf (" g has already existed.\n");
			return 0;
		}
			
		/* move */
		int i = cur_rlp->tail, len = i + 1;

		/* free + malloc */
		struct rlp_range *new_array = (struct rlp_range *) malloc (sizeof(struct rlp_range) * (len + 1));

#ifdef DEBUG
		if (new_array == NULL) {
			printf ("rlp_insert: malloc fail.\n");
			exit (0);
		}
#endif
	
		while (i >= index) {
			new_array[i+1].child = array[i].child;
			new_array[i+1].g = array[i].g;
			new_array[i+1].count = array[i].count;
			new_array[i+1].dim =  array[i].dim;
			new_array[i+1].action = array[i].action;
			new_array[i+1].prior = array[i].prior;
			i--;
		}
		
		new_array[index].child = new_child;
                new_array[index].g = new_g;
                new_array[index].count = new_count;
                new_array[index].dim = dim;
		new_array[index].action = new_action;
		new_array[index].prior =  new_prior;
		
		i = index -1;
		while (i >= 1) {
                        new_array[i].child = array[i].child;
                        new_array[i].g = array[i].g;
                        new_array[i].count = array[i].count;
                        new_array[i].dim =  array[i].dim;
                        new_array[i].action = array[i].action;
                        new_array[i].prior = array[i].prior;
                        i--;
                }

		/*free (array);*/
		free (cur_rlp->rangeArray); //for security
		array = NULL;

		cur_rlp->rangeArray = new_array;	/*point to new address*/
		cur_rlp->tail ++;		

		return 1;
	}
	else {
		printf("rlp_insert : cur_rlp is NULL,inpu the valid data\n");
		return 0;
	}
}


void MRLP_insert (struct rlp *cur_rlp, struct rule *new_rule, int cur_dim)
{
	/* add ranges if necessary */
	if (cur_rlp == NULL || new_rule == NULL) return;
	
	int index, action, prior;
	unsigned int count = 0;
	struct range *r = new_rule->fields[cur_dim];
	struct rlp_range *array = cur_rlp->rangeArray;	//original addr
	struct rlp *tmp;

	if (r->left > 0) {
		locate (r->left-1, cur_rlp, &index);

		if (index == 0 ) {
			printf ("MRLP_insert: left location is NULL.\n");
			return;
		}

#ifndef COMPRESS
		if (array[index].g >= r->left) {

			action = array[index].action;
			prior = array[index].prior;

			if (cur_rlp->leaf == '1') tmp = NULL;
			else MRLP_clone (array[index].child, &tmp);	//leaf range's child is NULL,bug panda

			rlp_insert (cur_rlp, r->left-1, tmp, cur_dim, array[index].count, action, prior);
		}
		else {
			index ++;	
			array[index].count ++;	//only:l->left-1=one point
		}
		
#else
		if (array[index].g >= r->left) {

			if (array[index].count != 0 && cur_rlp->leaf == '0') MRLP_clone (array[index].child, &tmp);
			else tmp = NULL;

			action = array[index].action;
                        prior = array[index].prior;
#ifdef DEBUG			
			printf ("insert l-1' rangearray[index].count is %d\n", array[index].count);
#endif
			rlp_insert (cur_rlp, r->left-1, tmp, cur_dim, array[index].count, action, prior);
		}
#endif
	}
	
	array = cur_rlp->rangeArray;  /*may new addr, for consistancy*/

	count = 0, index = 0, tmp = NULL;
	locate (r->right, cur_rlp, &index);
#ifdef DEBUG
	if (index == 0) {
		printf ("MRLP_insert: right location is NULL.\n");
		return ;
	}
#endif

#ifndef COMPRESS
	if (array[index].g > r->right) {
		
		/*don't modify the action at here.*/
		action = array[index].action;
		prior = array[index].prior;

		if (cur_rlp->leaf == '1') tmp = NULL;
		else MRLP_clone (array[index].child, &tmp);     //leaf range's child is NULL,bug panda

		rlp_insert (cur_rlp, r->right, tmp, cur_dim, array[index].count + 1, action, prior);
	}
	else {
		array[index].count ++;
	}
#else
	if (array[index].g > r->right) {
		
		if (cur_rlp->leaf == '1') tmp = NULL;
                else if (array[index].count == 0) build_empty_tree (&tmp, cur_dim + 1);	
		else MRLP_clone (array[index].child, &tmp);

		action = array[index].action;
                prior = array[index].prior;
		
		rlp_insert (cur_rlp, r->right, tmp, cur_dim, array[index].count, action, prior); 
	}
#endif

	array = cur_rlp->rangeArray;  /*may new addr, for consistance*/

	/* iterate handle overlapped ranges */
	index = 0;
	locate (r->left, cur_rlp, &index);
	int iter = index;


#ifndef COMPRESS
	if (cur_dim == DIM_NUM-1) { 
		while ((iter <= cur_rlp->tail) && array[iter].g <= r->right) {
			if (array[iter].prior > new_rule->prior) {
				array[iter].prior = new_rule->prior;
				array[iter].action = new_rule->action;
			}
			iter ++;
		}
	}
	else {
		/* non-terminal cases , won't modify the covered ranges action*/
		while ((iter <= cur_rlp->tail) && (array[iter].g <= r->right)) {
			MRLP_insert (array[iter].child, new_rule, cur_dim+1);
			iter ++;
		}
	}
#else
	if (cur_dim == DIM_NUM-1) {
                while ((iter <= cur_rlp->tail) && array[iter].g <= r->right) {
			array[iter].count ++;
			if (array[iter].prior > new_rule->prior) {
                                array[iter].prior = new_rule->prior;
                                array[iter].action = new_rule->action;
                        }
                        iter ++;
                }
        }
        else {
                /* non-terminal cases , won't modify the covered ranges action*/
                while ((iter <= cur_rlp->tail) && (array[iter].g <= r->right)) {

			if (array[iter].child == NULL) { 	/* important modification  */
				build_empty_tree (&array[iter].child, cur_dim + 1);
			}
			array[iter].count++;
#ifdef DEBUG
                        printf ("iterate covered ranges : array[iter].count is %d ,  array[iter].child is %ld \n",array[iter].count, (unsigned long)array[iter].child);
#endif
                        MRLP_insert (array[iter].child, new_rule, cur_dim+1);
                        iter ++;
                }
        }
#endif
}

/*
char *action_lookup (int action)
{
	char *ret;
	switch (action)
	{
		case 1 : ret = "FORWARD";
			 break;

		case 2 : ret = "DROP"; 
			 break;
		case 10000 : ret = "DEFAULT";
			     break;
		default : printf("invalid action.\n");
	}
	return ret;
}
*/


int pkt_generator (unsigned int *fields)	//fields: sip, dip, sport, dport, prot
{
	if (fields == NULL) {
		printf ("pkt_generate: para is NULL.\n");
		exit (0);
	}		

	int j = 0;

	while (j <5) {
		if (j < 2) {
			 fields[j] = (rand() >> 4) % 0xFFFFFFFF;
		}
		else if (j == 2 || j == 3) {
			fields[j] = (rand() >> 4)  % 0xFFFF;
		}
		else {
			fields[j] = (rand() >> 4) % 0xFF;	//protocol: __u8
		}
		j ++;
	}

	return 0;
}

void check_rule (unsigned int *l, unsigned int *r)
{
	unsigned int tmp;
	if (*l > *r)	//rule: l > r, swap
	{
		tmp = *l;
		*l = *r;
		*r = tmp;
	}
}


void rlp_traverse (struct rlp *root)
{
	if (root == NULL) return;

	struct rlp_range *tmp = root->rangeArray;
	int i = 1, end = root->tail;

	while (i <= end) {
		printf ("%ld ", (unsigned long)tmp[i].g);
		i ++;
	}
	printf("\n");
}



void MRLP_traverse (struct rlp *root)
{
	if (root == NULL) return;
	printf ("\n");
	
	struct rlp_range *tmp = root->rangeArray;
 	rlp_traverse (root);
	int i = 1, end = root->tail;
	while (i <= end)
	{
		MRLP_traverse (tmp[i].child);
		i ++;
	}
	
}


void MRLP_free (struct rlp *root)
{
	if (root == NULL) {
		printf ("root is NULL, free fail.\n");
		return;
	}

	int i = 1, end = root->tail;
	struct rlp_range *array = root->rangeArray;
	
	if (root->leaf == '1') {
		free (root->rangeArray);
		free (root);
	}
	else {
		while (i <= end) {

			if (array[i].child != NULL) MRLP_free (array[i].child);
			i ++;
		}
		free (root->rangeArray);
		free (root); 
	}
}

int build_rule_tree (struct rlp *l, struct rule *r)
{
	unsigned int tmp = 0;

	if (r == NULL) {
		printf ("build_rule_tree: rule is NULL.\n");
		exit (0);
	}
	if (l == NULL) {
		printf ("build_rule_tree: root is NULL.\n");
		exit (0);
	}
	int i, j = 0;
	while (j < rule_num) {
		for (i = 0; i < 5; i++) {
			if (i < 2) tmp = 0xFFFFFFFF;
			else tmp = 0xFFFF;

			r->fields[i]->left = (rand() >> 4) % tmp;
			r->fields[i]->right = (rand() >> 4) % tmp;	
			check_rule (&r->fields[i]->left, &r->fields[i]->right);
		}

		r->action =	2;	//rand() % 2 + 1;
		r->prior = (rand() >> 4) % 10000;

		MRLP_insert (l, r, 0);

		j ++;
	}
	return 1;
}
	
int HiPAC(char *chunk_buf, int len, struct rlp *l)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ethh = (struct ethhdr *)chunk_buf;
	iph = (struct iphdr *)(chunk_buf + 1);
	tcph = (struct tcphdr *)(chunk_buf + sizeof(struct ethhdr) + 4 * iph->ihl);
	__be32 saddr, daddr;
	__be16 src, dest;
	__u8 prot;
	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	prot = ntohs(iph->protocol);
	src = ntohs(tcph->source);
	dest = ntohs(tcph->dest);
	
	unsigned int *fields = (unsigned int *)malloc (sizeof(unsigned int)*5);
	fields[0] = saddr;
	fields[1] = daddr;
	fields[2] = src;
	fields[3] = dest;
	fields[4] = prot;

	int action = MRLP_search(fields, l);
	return action;
}

int init_rlp_tree(struct rlp *l)
{		
	struct rule *r = (struct rule *)malloc (sizeof(struct rule));
	int i;
	
	init (l);
	
#ifdef TRAVERSE
	printf ("\n init tree: \n");
	MRLP_traverse (l);
#endif

	srand((int)time(0));
	
	for (i = 0; i < 5; i++) {
		r->fields[i] = (struct range *)malloc (sizeof(struct range));
	}

	if (build_rule_tree (l, r) <= 0) return -1;
	
	for (i =0 ; i <5 ; i++) {
		free (r->fields[i]);
	}
	free (r);
	r = NULL;

#ifdef TRAVERSE
	printf ("\n rule tree: \n");
	MRLP_traverse (l);
#endif

	return 0;
}
