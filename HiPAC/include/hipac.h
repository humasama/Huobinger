/*
#ifndef _HIPAC_H_
#define _HIPAC_H_
*/

#define DIM_NUM 5
#define MAX_EDGE 0xFFFFFFFF	//0~0xFFFFFFFFFFF
#define DEF_PRIOR 10000
//typedef unsigned char bool;	//conflict with fw

struct range {
	unsigned int left;
	unsigned int right;
};

struct rule {
	struct range *fields[DIM_NUM]; 
	int action;
	int prior;
};

struct rlp_range {
	struct rlp *child;
	unsigned int g;	//right edge as the mark of a range.
	int count;
	int prior;
	int dim;
	int action;	//when leaf=1,has meaning	
};

struct rlp {
	//int leaf;
	unsigned char leaf;
	struct rlp_range *rangeArray;
	int tail;
};

enum{
	FORWARD = 1,
	DROP,
//	DEF_ACT,
};


int locate (unsigned int key, struct rlp *cur_rlp, int *index);

void init (struct rlp *root);
void build_empty_tree (struct rlp **l, int insert_num);

int MRLP_search (unsigned int *fields, struct rlp *root);
int rlp_search (unsigned int *fields, int cur_dim, struct rlp *cur_rlp);

int rlp_insert (struct rlp *cur_rlp, unsigned int new_g, struct rlp *new_child, int dim, int new_count, int new_action, int new_prior);
void rlp_clone (struct rlp * cur_rlp, struct rlp **l);
void MRLP_clone (struct rlp *cur_rlp, struct rlp **l);
void MRLP_insert (struct rlp *cur_rlp, struct rule *new_rule, int cur_dim);

void rlp_traverse (struct rlp *root);
void MRLP_traverse (struct rlp *root);

void MRLP_free (struct rlp *root);

int build_rule_tree (struct rlp *l, struct rule *r);

/* interface */
int HiPAC(char *chunk_buf, int len, struct rlp *l);
int init_rlp_tree(struct rlp *l);	/* just call once*/

int pkt_generator (unsigned int *fields);
void check_rule (unsigned int *l, unsigned int *r);

