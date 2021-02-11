#!/bin/bash

gcloud builds submit --substitutions=TAG_NAME=3.1.20
